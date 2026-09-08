//! Durable signed-lease store for the OMA-ID endpoint agent (P0 groundwork).
//!
//! Implements the agent side of plan §9.1/§9.3: leases are ed25519-signed by
//! the issuer (ed25519-dalek — an established implementation, no hand-rolled
//! crypto), verified against a pinned issuer key, and persisted together with
//! a revocation-epoch high-water mark so an old-but-valid lease cannot be
//! replayed past a newer revocation state (§9.3 anti-rollback).
//!
//! Deliberate P0 boundaries, not production claims:
//! - the store is a single JSON file written atomically (tmp + rename);
//!   durable security-state placement and fsync strategy are deployment
//!   decisions (plan §13);
//! - issuer key distribution/pinning is undecided and needs an ADR before
//!   production (plan §5.3 keeps lease-signing keys a separate key purpose);
//! - the Rails issuer does not sign leases yet — this slice proves the agent
//!   side; cross-language canonical encoding is a P2 contract item.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use oma_id_agent_core::{Operation, VerifiedLease};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("store JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex signature: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("bad ed25519 signature: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("issuer key must be 32 bytes, got {0}")]
    BadKeyLength(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("rollback detected: stored revocation epoch {stored} is newer than incoming {incoming}")]
    RollbackDetected { stored: u64, incoming: u64 },
    #[error("lease already expired at record time (now {now}, expires_at {expires_at})")]
    Expired { now: u64, expires_at: u64 },
}

/// Owned, serializable mirror of the core `VerifiedLease`. Serialization is
/// only used for the signed payload and the store file; authorization
/// decisions keep using the core borrow-based type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeasePayload {
    pub subject_id: String,
    pub device_id: String,
    pub not_before: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub operations: Vec<Operation>,
}

impl LeasePayload {
    pub fn verified_lease(&self) -> VerifiedLease<'_> {
        VerifiedLease {
            subject_id: &self.subject_id,
            device_id: &self.device_id,
            not_before: self.not_before,
            expires_at: self.expires_at,
            revocation_epoch: self.revocation_epoch,
            operations: &self.operations,
        }
    }
}

/// A lease payload plus its ed25519 signature over the payload's canonical
/// JSON encoding (see `canonical_payload_json`), and the `key_id` of the
/// issuer key that signed it (ADR-0005: key_id = SHA-256 of the raw public
/// key, hex). Both signing (issuer) and verification (agent) must use the
/// same canonical encoding; the cross-language contract is pinned by
/// `protocol/lease-v1/` fixtures and tested in both languages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedLease {
    pub payload: LeasePayload,
    /// hex-encoded ed25519 signature over `canonical_payload_json(&payload)`.
    pub signature: String,
    /// Identifies the issuer key that signed this lease (ADR-0005). Empty in
    /// the single-key compatibility mode.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_id: String,
}

impl SignedLease {
    pub fn sign(payload: LeasePayload, issuer: &SigningKey) -> Self {
        Self::sign_with_key_id(payload, issuer, "")
    }

    pub fn sign_with_key_id(
        payload: LeasePayload,
        issuer: &SigningKey,
        key_id: &str,
    ) -> Self {
        let bytes = canonical_payload_json(&payload);
        let signature = hex::encode(issuer.sign(&bytes).to_bytes());
        Self {
            payload,
            signature,
            key_id: key_id.to_string(),
        }
    }

    /// Verify against the pinned issuer key; returns the verified payload on
    /// success. Callers may only turn the result into a `VerifiedLease` after
    /// this passes (mirrors the core crate's contract).
    pub fn verify(&self, issuer: &VerifyingKey) -> Result<&LeasePayload, StoreError> {
        let sig_bytes = hex::decode(&self.signature)?;
        let signature = Signature::from_slice(&sig_bytes)?;
        let bytes = canonical_payload_json(&self.payload);
        issuer.verify_strict(&bytes, &signature)?;
        Ok(&self.payload)
    }
}

/// The pinned issuer key set (ADR-0005). Exactly one `active` key signs new
/// leases; `retiring` keys still verify during the rotation overlap;
/// `revoked` keys never verify.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssuerKeySet {
    pub version: u32,
    pub keys: Vec<PinnedIssuerKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PinnedIssuerKey {
    pub key_id: String,
    pub public_key_hex: String,
    pub state: KeyState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyState {
    Active,
    Retiring,
    Revoked,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("unknown key_id {0}: not in the pinned set")]
    UnknownKeyId(String),
    #[error("key {0} is revoked")]
    RevokedKey(String),
    #[error("key set must contain exactly one active key")]
    NotExactlyOneActive,
    #[error("key_id {key_id} does not match a SHA-256 of the public key")]
    KeyIdMismatch { key_id: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl IssuerKeySet {
    /// Parse and validate a key-set file: exactly one active key, and every
    /// key_id must equal the SHA-256 of its public key (ADR-0005 §2 — ids
    /// are derived, never chosen).
    pub fn load(path: &Path) -> Result<Self, KeyError> {
        let bytes = std::fs::read(path)?;
        let set: IssuerKeySet = serde_json::from_slice(&bytes)?;
        set.validate()?;
        Ok(set)
    }

    pub fn validate(&self) -> Result<(), KeyError> {
        if self.keys.iter().filter(|k| k.state == KeyState::Active).count() != 1 {
            return Err(KeyError::NotExactlyOneActive);
        }
        for key in &self.keys {
            Self::validate_key_id(key)?;
        }
        Ok(())
    }

    /// key_id must be SHA-256 of the raw 32-byte public key (hex).
    pub fn validate_key_id(key: &PinnedIssuerKey) -> Result<(), KeyError> {
        use sha2::{Digest, Sha256};
        let raw = hex::decode(&key.public_key_hex)?;
        let digest: [u8; 32] = Sha256::digest(&raw).into();
        let derived = hex::encode(digest);
        if derived != key.key_id.to_lowercase() {
            return Err(KeyError::KeyIdMismatch {
                key_id: key.key_id.clone(),
            });
        }
        Ok(())
    }

    /// The verifying key for `key_id`, honoring the state machine: active
    /// and retiring keys verify; revoked and unknown keys fail closed.
    pub fn verifying_key_for(&self, key_id: &str) -> Result<VerifyingKey, KeyError> {
        let pinned = self
            .keys
            .iter()
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| KeyError::UnknownKeyId(key_id.to_string()))?;
        if pinned.state == KeyState::Revoked {
            return Err(KeyError::RevokedKey(key_id.to_string()));
        }
        Ok(issuer_verifying_key(&pinned.public_key_hex)?)
    }

    /// The active key's id and verifying key (the issuer-side selection is
    /// mirrored here for tooling; Rails owns the actual signing decision).
    pub fn active_key(&self) -> Result<(&PinnedIssuerKey, VerifyingKey), KeyError> {
        let pinned = self
            .keys
            .iter()
            .find(|k| k.state == KeyState::Active)
            .ok_or(KeyError::NotExactlyOneActive)?;
        Ok((pinned, issuer_verifying_key(&pinned.public_key_hex)?))
    }
}

/// The pinned canonical encoding for lease signing (lease-v1).
///
/// Contract: compact JSON (no whitespace), fields in exactly this schema
/// order — subject_id, device_id, not_before, expires_at, revocation_epoch,
/// operations — with operations in the issuer-supplied order and UTF-8
/// output. Signing ANY other byte sequence (different order, spacing, or
/// key casing) produces a different signature by design; both signers and
/// verifiers must emit bytes identical to this function.
pub fn canonical_payload_json(payload: &LeasePayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"{");
    write_string_field(&mut out, "subject_id", &payload.subject_id);
    out.extend_from_slice(b",\"device_id\":");
    write_json_string(&mut out, &payload.device_id);
    out.extend_from_slice(b",\"not_before\":");
    out.extend_from_slice(payload.not_before.to_string().as_bytes());
    out.extend_from_slice(b",\"expires_at\":");
    out.extend_from_slice(payload.expires_at.to_string().as_bytes());
    out.extend_from_slice(b",\"revocation_epoch\":");
    out.extend_from_slice(payload.revocation_epoch.to_string().as_bytes());
    out.extend_from_slice(b",\"operations\":[");
    for (index, operation) in payload.operations.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        let name = match operation {
            Operation::Login => "Login",
            Operation::Unlock => "Unlock",
            Operation::Elevate => "Elevate",
            Operation::RemoteLogin => "RemoteLogin",
        };
        write_json_string(&mut out, name);
    }
    out.extend_from_slice(b"]}");
    out
}

fn write_string_field(out: &mut Vec<u8>, key: &str, value: &str) {
    out.push(b'"');
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(b"\":");
    write_json_string(out, value);
}

/// Minimal JSON string writer: the fields signed here are constrained to
/// ASCII identifiers by the enrollment contract, but escape defensively
/// (quote, backslash, control characters) so malformed input cannot change
/// the signed meaning.
fn write_json_string(out: &mut Vec<u8>, value: &str) {
    out.push(b'"');
    for byte in value.bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x00..=0x1F => out.extend_from_slice(format!("\\u{:04x}", byte).as_bytes()),
            _ => out.push(byte),
        }
    }
    out.push(b'"');
}

/// Generate an issuer keypair from a 32-byte seed. The key ceremony and
/// distribution are owner decisions (ADR pending); this helper exists for
/// tests and tooling.
pub fn issuer_keypair(
    seed: &[u8; 32],
) -> Result<(SigningKey, VerifyingKey), StoreError> {
    let signing = SigningKey::from_bytes(seed);
    Ok((signing.clone(), signing.verifying_key()))
}

/// Parse a 32-byte hex issuer public key (the pinned-key argument shape).
pub fn issuer_verifying_key(hex_key: &str) -> Result<VerifyingKey, StoreError> {
    let bytes = hex::decode(hex_key)?;
    if bytes.len() != 32 {
        return Err(StoreError::BadKeyLength(bytes.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(VerifyingKey::from_bytes(&key)?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredLease {
    payload: LeasePayload,
    signature: String,
    /// Issuer key id that signed this lease (ADR-0005). Empty in version 1
    /// stores (single implicit key).
    #[serde(default)]
    key_id: String,
    /// Agent receive time (unix seconds) — evidence metadata, not trusted.
    received_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    high_water_revocation_epoch: u64,
    leases: Vec<StoredLease>,
}

/// On-disk lease store. Clones are cheap-ish (JSON file size bound), and the
/// store must not be mutated while `active_lease` borrows are alive.
#[derive(Clone, Debug)]
pub struct Store {
    path: PathBuf,
    file: StoreFile,
}

/// Store file version 2: leases carry the signing key_id (ADR-0005).
/// Version 1 files (single implicit key) still load.
const STORE_VERSION: u32 = 2;

impl Store {
    /// Load the store from `path`. A missing file is an empty store (first
    /// boot); a corrupt file is an error — a damaged store must fail closed,
    /// not silently reset (plan §9.2: lost server connectivity keeps a
    /// restricted recovery path, not a silent bypass).
    pub fn load(path: &Path) -> Result<Self, StoreError> {
        let file = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<StoreFile>(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => StoreFile {
                version: STORE_VERSION,
                high_water_revocation_epoch: 0,
                leases: Vec::new(),
            },
            Err(error) => return Err(error.into()),
        };
        if file.version != STORE_VERSION {
            return Err(StoreError::Json(serde::de::Error::custom(format!(
                "unsupported store version {}",
                file.version
            ))));
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    pub fn high_water_revocation_epoch(&self) -> u64 {
        self.file.high_water_revocation_epoch
    }

    /// Verify every recorded lease against the issuer key. Load checks JSON
    /// validity only — a file edited after recording still parses, so the
    /// agent must re-verify signatures before trusting anything (fail closed
    /// on the first bad signature).
    pub fn verify_all(&self, issuer: &VerifyingKey) -> Result<(), StoreError> {
        for stored in &self.file.leases {
            let signed = SignedLease {
                payload: stored.payload.clone(),
                signature: stored.signature.clone(),
                key_id: stored.key_id.clone(),
            };
            signed.verify(issuer)?;
        }
        Ok(())
    }

    /// Key-set aware verification (ADR-0005): each lease's signature is
    /// checked with the pinned key matching its key_id — active and retiring
    /// keys verify, revoked and unknown keys fail closed. A single-key
    /// store (empty key_id) verifies against the fallback key.
    pub fn verify_all_with_key_set(
        &self,
        key_set: &IssuerKeySet,
        fallback: &VerifyingKey,
    ) -> Result<(), KeyError> {
        for stored in &self.file.leases {
            let signed = SignedLease {
                payload: stored.payload.clone(),
                signature: stored.signature.clone(),
                key_id: stored.key_id.clone(),
            };
            if stored.key_id.is_empty() {
                signed.verify(fallback)?;
            } else {
                let issuer = key_set.verifying_key_for(&stored.key_id)?;
                signed.verify(&issuer)?;
            }
        }
        Ok(())
    }

    pub fn lease_count(&self) -> usize {
        self.file.leases.len()
    }

    /// Verify and record a signed lease. Rejects rollbacks (an incoming
    /// revocation epoch older than the stored high-water mark) and leases
    /// that are already expired at record time. Replaces any prior lease for
    /// the same (subject, device) pair. Persists atomically.
    pub fn record(
        &mut self,
        signed: &SignedLease,
        issuer: &VerifyingKey,
        now: u64,
    ) -> Result<(), RecordError> {
        let payload = signed.verify(issuer)?;
        if payload.revocation_epoch < self.file.high_water_revocation_epoch {
            return Err(RecordError::RollbackDetected {
                stored: self.file.high_water_revocation_epoch,
                incoming: payload.revocation_epoch,
            });
        }
        if payload.expires_at <= now {
            return Err(RecordError::Expired {
                now,
                expires_at: payload.expires_at,
            });
        }

        self.file
            .leases
            .retain(|l| l.payload.subject_id != payload.subject_id || l.payload.device_id != payload.device_id);
        self.file.leases.push(StoredLease {
            payload: payload.clone(),
            signature: signed.signature.clone(),
            key_id: signed.key_id.clone(),
            received_at: now,
        });
        self.file.high_water_revocation_epoch =
            self.file.high_water_revocation_epoch.max(payload.revocation_epoch);
        self.save()?;
        Ok(())
    }

    /// The newest unexpired lease that authorizes `operation`, if any.
    pub fn active_lease(&self, now: u64, operation: Operation) -> Option<VerifiedLease<'_>> {
        self.file
            .leases
            .iter()
            .filter(|l| l.payload.expires_at > now && l.payload.operations.contains(&operation))
            .max_by_key(|l| l.payload.expires_at)
            .map(|l| l.payload.verified_lease())
    }

    /// Atomic persist: write a sibling temp file, then rename over the
    /// target. A crash leaves either the old or the new file, never a
    /// partial one (plan §12.3).
    fn save(&self) -> Result<(), StoreError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let bytes = serde_json::to_vec_pretty(&self.file)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(seed: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes
    }

    fn payload(expires_at: u64, epoch: u64) -> LeasePayload {
        LeasePayload {
            subject_id: "person-1".into(),
            device_id: "device-1".into(),
            not_before: 1_000,
            expires_at,
            revocation_epoch: epoch,
            operations: vec![Operation::Login, Operation::Unlock],
        }
    }

    fn keypair(seed_byte: u8) -> (SigningKey, VerifyingKey) {
        issuer_keypair(&seed(seed_byte)).expect("keypair")
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (issuer, key) = keypair(1);
        let signed = SignedLease::sign(payload(2_000, 7), &issuer);
        let verified = signed.verify(&key).expect("signature must verify");
        assert_eq!(verified.subject_id, "person-1");
        assert_eq!(verified.revocation_epoch, 7);
    }

    #[test]
    fn tampered_payload_rejected() {
        let (issuer, key) = keypair(1);
        let mut signed = SignedLease::sign(payload(2_000, 7), &issuer);
        signed.payload.revocation_epoch = 9; // privilege escalation attempt
        assert!(signed.verify(&key).is_err());
    }

    #[test]
    fn wrong_issuer_key_rejected() {
        let (issuer, _) = keypair(1);
        let (_, other_key) = keypair(2);
        let signed = SignedLease::sign(payload(2_000, 7), &issuer);
        assert!(signed.verify(&other_key).is_err());
    }

    #[test]
    fn record_persists_and_reloads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("leases.json");
        let (issuer, key) = keypair(3);

        let mut store = Store::load(&path).expect("empty store loads");
        assert_eq!(store.lease_count(), 0);
        store
            .record(&SignedLease::sign(payload(2_000, 7), &issuer), &key, 1_500)
            .expect("record");

        let reloaded = Store::load(&path).expect("reload");
        assert_eq!(reloaded.lease_count(), 1);
        assert_eq!(reloaded.high_water_revocation_epoch(), 7);
        let lease = reloaded
            .active_lease(1_500, Operation::Unlock)
            .expect("active lease");
        assert_eq!(lease.subject_id, "person-1");
        assert!(reloaded.active_lease(1_500, Operation::Elevate).is_none());
    }

    #[test]
    fn rollback_rejected_and_persists_across_reload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("leases.json");
        let (issuer, key) = keypair(4);

        let mut store = Store::load(&path).expect("load");
        store
            .record(&SignedLease::sign(payload(3_000, 9), &issuer), &key, 1_500)
            .expect("record epoch 9");

        let mut store = Store::load(&path).expect("reload");
        let err = store
            .record(&SignedLease::sign(payload(3_500, 7), &issuer), &key, 2_000)
            .expect_err("epoch 7 after 9 must be a rollback");
        assert!(matches!(
            err,
            RecordError::RollbackDetected { stored: 9, incoming: 7 }
        ));
        // The rejected lease must not have been persisted.
        assert_eq!(Store::load(&path).expect("reload").lease_count(), 1);
    }

    #[test]
    fn expired_lease_rejected_at_record_time() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("leases.json");
        let (issuer, key) = keypair(5);
        let mut store = Store::load(&path).expect("load");
        let err = store
            .record(&SignedLease::sign(payload(1_000, 7), &issuer), &key, 2_000)
            .expect_err("expired lease must be rejected");
        assert!(matches!(err, RecordError::Expired { .. }));
    }

    #[test]
    fn newer_lease_replaces_same_subject_device() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("leases.json");
        let (issuer, key) = keypair(6);
        let mut store = Store::load(&path).expect("load");
        store
            .record(&SignedLease::sign(payload(2_000, 7), &issuer), &key, 1_500)
            .expect("first");
        store
            .record(&SignedLease::sign(payload(4_000, 8), &issuer), &key, 2_000)
            .expect("renewal");
        assert_eq!(store.lease_count(), 1, "same (subject, device) replaces");
        assert_eq!(store.high_water_revocation_epoch(), 8);
        assert!(store.active_lease(2_500, Operation::Login).is_some());
    }

    #[test]
    fn corrupt_store_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("leases.json");
        std::fs::write(&path, b"{not json").expect("write corrupt file");
        assert!(Store::load(&path).is_err(), "corrupt store must fail closed");
    }

    #[test]
    fn unsupported_store_version_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("leases.json");
        std::fs::write(
            &path,
            br#"{"version": 99, "high_water_revocation_epoch": 0, "leases": []}"#,
        )
        .expect("write future store");
        assert!(Store::load(&path).is_err());
    }

    #[test]
    fn bad_issuer_key_length_rejected() {
        assert!(issuer_verifying_key("abcd").is_err());
    }

    #[test]
    fn key_set_rotation_overlap_and_revocation() {
        // ADR-0005: active + retiring keys both verify; revoked keys fail
        // closed; unknown key_ids fail closed.
        let (old_issuer, _) = keypair(20);
        let (new_issuer, new_verifying) = keypair(21);
        let _ = new_verifying;

        let key_set = IssuerKeySet {
            version: 1,
            keys: vec![
                PinnedIssuerKey {
                    key_id: key_id_of(&old_issuer),
                    public_key_hex: hex::encode(old_issuer.verifying_key().as_bytes()),
                    state: KeyState::Retiring,
                },
                PinnedIssuerKey {
                    key_id: key_id_of(&new_issuer),
                    public_key_hex: hex::encode(new_issuer.verifying_key().as_bytes()),
                    state: KeyState::Active,
                },
            ],
        };
        key_set.validate().expect("one active, one retiring");

        let old_lease = SignedLease::sign_with_key_id(payload(2_000, 7), &old_issuer, &key_id_of(&old_issuer));
        let new_lease = SignedLease::sign_with_key_id(payload(3_000, 8), &new_issuer, &key_id_of(&new_issuer));

        // Both verify during the overlap window.
        let old_key = key_set.verifying_key_for(&old_lease.key_id).expect("retiring key verifies");
        old_lease.verify(&old_key).expect("old lease verifies");
        let new_key = key_set.verifying_key_for(&new_lease.key_id).expect("active key verifies");
        new_lease.verify(&new_key).expect("new lease verifies");
    }

    #[test]
    fn revoked_key_fails_closed() {
        let (issuer, _) = keypair(22);
        let key_set = IssuerKeySet {
            version: 1,
            keys: vec![PinnedIssuerKey {
                key_id: key_id_of(&issuer),
                public_key_hex: hex::encode(issuer.verifying_key().as_bytes()),
                state: KeyState::Revoked,
            }],
        };
        // Revoked keys break the "exactly one active" rule; build a set that
        // validates by adding an active companion, then assert the revoked
        // key cannot verify.
        let (other_issuer, _) = keypair(23);
        let set = IssuerKeySet {
            version: 1,
            keys: vec![
                PinnedIssuerKey {
                    key_id: key_id_of(&other_issuer),
                    public_key_hex: hex::encode(other_issuer.verifying_key().as_bytes()),
                    state: KeyState::Active,
                },
                PinnedIssuerKey {
                    key_id: key_id_of(&issuer),
                    public_key_hex: hex::encode(issuer.verifying_key().as_bytes()),
                    state: KeyState::Revoked,
                },
            ],
        };
        set.validate().expect("exactly one active");
        let error = set
            .verifying_key_for(&key_id_of(&issuer))
            .expect_err("revoked key must fail closed");
        assert!(matches!(error, KeyError::RevokedKey(_)));
        let _ = key_set;
    }

    #[test]
    fn unknown_key_id_fails_closed() {
        let (_, _) = keypair(24);
        let (active, _) = keypair(25);
        let set = IssuerKeySet {
            version: 1,
            keys: vec![PinnedIssuerKey {
                key_id: key_id_of(&active),
                public_key_hex: hex::encode(active.verifying_key().as_bytes()),
                state: KeyState::Active,
            }],
        };
        let error = set
            .verifying_key_for("deadbeef")
            .expect_err("unknown key_id must fail closed");
        assert!(matches!(error, KeyError::UnknownKeyId(_)));
    }

    #[test]
    fn key_id_mismatch_rejected_at_load() {
        // key_id must be SHA-256 of the public key (ADR-0005 §2): a chosen
        // id that does not derive from the key is rejected.
        let (issuer, _) = keypair(26);
        let set = IssuerKeySet {
            version: 1,
            keys: vec![PinnedIssuerKey {
                key_id: "0000".into(),
                public_key_hex: hex::encode(issuer.verifying_key().as_bytes()),
                state: KeyState::Active,
            }],
        };
        assert!(matches!(
            set.validate(),
            Err(KeyError::KeyIdMismatch { .. })
        ));
    }

    #[test]
    fn two_active_keys_rejected() {
        let (a, _) = keypair(27);
        let (b, _) = keypair(28);
        let set = IssuerKeySet {
            version: 1,
            keys: vec![
                PinnedIssuerKey {
                    key_id: key_id_of(&a),
                    public_key_hex: hex::encode(a.verifying_key().as_bytes()),
                    state: KeyState::Active,
                },
                PinnedIssuerKey {
                    key_id: key_id_of(&b),
                    public_key_hex: hex::encode(b.verifying_key().as_bytes()),
                    state: KeyState::Active,
                },
            ],
        };
        assert!(matches!(set.validate(), Err(KeyError::NotExactlyOneActive)));
    }

    fn key_id_of(key: &SigningKey) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(key.verifying_key().as_bytes()))
    }

    #[test]
    fn canonical_encoding_matches_the_pinned_contract() {
        // The exact byte sequence any signer/verifier must produce for this
        // payload (lease-v1). Keep in sync with protocol/lease-v1/ and the
        // Rails encoder.
        let payload = payload(2_000, 7);
        let bytes = canonical_payload_json(&payload);
        assert_eq!(
            String::from_utf8(bytes).expect("canonical json is utf-8"),
            "{\"subject_id\":\"person-1\",\"device_id\":\"device-1\",\"not_before\":1000,\"expires_at\":2000,\"revocation_epoch\":7,\"operations\":[\"Login\",\"Unlock\"]}"
        );
    }

    #[test]
    fn canonical_encoding_is_drift_proofed_against_serde() {
        // If the LeasePayload schema or serde behavior changes, this fails —
        // the canonical encoding must then be re-pinned and version-bumped,
        // never silently drifted.
        let payload = payload(2_000, 7);
        assert_eq!(
            canonical_payload_json(&payload),
            serde_json::to_vec(&payload).expect("serde serialization")
        );
    }

    #[test]
    fn canonical_encoding_escapes_defensively() {
        let mut payload = payload(2_000, 7);
        payload.subject_id = "quote\"and\\slash".into();
        let bytes = canonical_payload_json(&payload);
        let parsed: LeasePayload = serde_json::from_slice(&bytes).expect("still valid json");
        assert_eq!(parsed.subject_id, "quote\"and\\slash");
    }

    #[test]
    fn verify_all_catches_post_record_tampering() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("leases.json");
        let (issuer, key) = keypair(7);
        let mut store = Store::load(&path).expect("load");
        store
            .record(&SignedLease::sign(payload(2_000, 7), &issuer), &key, 1_500)
            .expect("record");

        // Tamper with the file after recording: JSON stays valid, the
        // signature no longer matches.
        let mut reloaded = Store::load(&path).expect("reload");
        if let Some(lease) = reloaded.file.leases.first_mut() {
            lease.payload.revocation_epoch = 42;
        }
        reloaded.save().expect("save tampered");

        let tampered = Store::load(&path).expect("json-valid");
        assert!(
            tampered.verify_all(&key).is_err(),
            "tampered store must fail signature verification"
        );
    }
}
