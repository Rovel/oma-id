//! The OMA-ID endpoint agent (P2 slice): a privileged daemon that
//! periodically checks in with the Rails issuer over HTTPS, records the
//! signed leases it receives into the durable store (signature verification
//! + revocation-epoch high-water mark), and serves the local PAM socket from
//! that live store.
//!
//! Device identity (§7.4): an ed25519 key pair in the agent state directory
//! (0600, disk-encryption boundary; hardware-backed storage is later work).
//! Check-ins are signed with the device key; the server verifies against the
//! registered device public key (technician pre-provisioning, §6.3 — the
//! full enrollment transaction is P3).
//!
//! Trust chain: every lease is issuer-signed (lease-v1) and verified against
//! the pinned issuer key set (ADR-0005) before it can authorize anything.

use ed25519_dalek::{Signer, SigningKey};
use oma_id_agent_store::{
    issuer_verifying_key, IssuerKeySet, LeasePayload, PinnedIssuerKey, SignedLease, Store,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("agent I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("agent JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http check-in: {0}")]
    Http(String),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("ed25519: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),
    #[error("{0}")]
    Message(String),
}

impl From<oma_id_agent_store::KeyError> for AgentError {
    fn from(error: oma_id_agent_store::KeyError) -> Self {
        AgentError::Message(error.to_string())
    }
}

impl From<oma_id_agent_store::StoreError> for AgentError {
    fn from(error: oma_id_agent_store::StoreError) -> Self {
        AgentError::Message(error.to_string())
    }
}

/// Agent configuration (a JSON file; documented in the binary's help).
#[derive(Clone, Debug, Deserialize)]
pub struct AgentConfig {
    pub server_url: String,
    pub device_id: String,
    pub state_dir: PathBuf,
    pub socket_path: PathBuf,
    /// Seconds between check-ins (§11.2: proposed normal interval 300s).
    #[serde(default = "default_check_in_interval")]
    pub check_in_interval_seconds: u64,
}

fn default_check_in_interval() -> u64 {
    300
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self, AgentError> {
        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn device_key_path(&self) -> PathBuf {
        self.state_dir.join("device.key")
    }

    pub fn key_set_path(&self) -> PathBuf {
        self.state_dir.join("issuer-keys.json")
    }

    pub fn store_path(&self) -> PathBuf {
        self.state_dir.join("leases.json")
    }
}

/// The agent's device identity: an ed25519 key pair persisted (0600) in the
/// state directory. Per-device credential, separate from every user
/// credential (§11.1). Hardware-backed storage is later work (§7.1).
pub struct DeviceIdentity {
    pub signing_key: SigningKey,
    pub public_key_hex: String,
}

impl DeviceIdentity {
    /// Load the device key from `path`, generating and persisting a new one
    /// (0600) on first boot. The public key is what the operator registers
    /// out-of-band (technician pre-provisioning, §6.3).
    pub fn load_or_create(path: &Path) -> Result<Self, AgentError> {
        if let Ok(bytes) = std::fs::read(path) {
            let seed = bytes
                .get(..32)
                .ok_or_else(|| AgentError::Message("device key file must be 32 bytes".into()))?;
            let mut seed_array = [0u8; 32];
            seed_array.copy_from_slice(seed);
            return Ok(Self::from_signing_key(SigningKey::from_bytes(&seed_array)));
        }
        let signing_key = SigningKey::from_bytes(&random_seed());
        let key_bytes = signing_key.to_bytes();
        let identity = Self::from_signing_key(signing_key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, key_bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(identity)
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        Self {
            public_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
            signing_key,
        }
    }
}

fn random_seed() -> [u8; 32] {
    // /dev/urandom read: a CSPRNG without pulling rand_core features. Linux
    // always provides it (plan platform is Omarchy/Arch).
    use std::io::Read;
    let mut seed = [0u8; 32];
    match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut seed)) {
        Ok(()) => seed,
        Err(_) => {
            // Unreachable on Linux; lab fallback keeps the agent buildable.
            let mut hasher = sha2::Sha256::new();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
            hasher.update(now.as_nanos().to_le_bytes());
            hasher.update(std::process::id().to_le_bytes());
            hasher.finalize().into()
        }
    }
}

/// The check-in request body (plan §11.2). P2 boundary: the signature covers
/// "device_id|timestamp" with a ±300s server-side replay window; §7.4
/// hardening (mTLS, server challenges) is later work.
#[derive(Serialize)]
pub struct CheckInRequest {
    pub device_id: String,
    pub timestamp: u64,
    pub signature_hex: String,
}

/// The check-in response: the store-file lease record plus the pinned issuer
/// key set (ADR-0005 distribution) and the current revocation epoch.
#[derive(Clone, Debug, Deserialize)]
pub struct CheckInResponse {
    pub version: u32,
    pub high_water_revocation_epoch: u64,
    pub leases: Vec<SignedLeaseWire>,
    pub key_id: String,
    #[serde(default)]
    pub issuer_keys: Vec<PinnedIssuerKey>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignedLeaseWire {
    pub payload: LeasePayload,
    pub signature: String,
    #[serde(default)]
    pub key_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CheckInError {
    #[error("http: {0}")]
    Http(String),
    #[error("server rejected the check-in ({status}): {body}")]
    Rejected { status: u16, body: String },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Perform one check-in: sign the request with the device key and POST it.
/// TLS verification is always on (§6.2: no certificate bypass).
pub fn check_in(
    server_url: &str,
    device_id: &str,
    identity: &DeviceIdentity,
) -> Result<CheckInResponse, CheckInError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let message = format!("{device_id}|{timestamp}");
    let signature = identity.signing_key.sign(message.as_bytes());

    let body = CheckInRequest {
        device_id: device_id.to_string(),
        timestamp,
        signature_hex: hex::encode(signature.to_bytes()),
    };

    let url = format!("{}/api/v1/device/check-ins", server_url.trim_end_matches('/'));
    let response = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(ureq::json!(&body));

    match response {
        Ok(parsed) => parsed
            .into_json::<CheckInResponse>()
            .map_err(|e| CheckInError::Http(format!("response decode: {e}"))),
        Err(ureq::Error::Status(status, response)) => {
            let body = response.into_string().unwrap_or_default();
            Err(CheckInError::Rejected { status, body })
        }
        Err(e) => Err(CheckInError::Http(e.to_string())),
    }
}

/// Apply a check-in response to the agent's store: persist the updated
/// pinned issuer key set (ADR-0005 §6 distribution), then record every lease
/// through the store's verified path — signature verification against the
/// matching pinned key and the anti-rollback HWM happen in `record`.
/// Returns the store's high-water revocation epoch.
pub fn apply_check_in(
    store: &mut Store,
    response: &CheckInResponse,
    key_set_path: &Path,
) -> Result<u64, AgentError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let key_set = if response.issuer_keys.is_empty() {
        None
    } else {
        let key_set = IssuerKeySet {
            version: 1,
            keys: response
                .issuer_keys
                .iter()
                .map(|k| PinnedIssuerKey {
                    key_id: k.key_id.clone(),
                    public_key_hex: k.public_key_hex.clone(),
                    state: k.state,
                })
                .collect(),
        };
        key_set.validate().map_err(|e| AgentError::Message(e.to_string()))?;
        persist_atomically(key_set_path, &serde_json::to_vec_pretty(&key_set)?)?;
        Some(key_set)
    };

    // Resolve the verifying key for each lease: key-set mode (key_id present)
    // or single-key fallback for key_id-less records.
    for lease in &response.leases {
        let signed = SignedLease {
            payload: lease.payload.clone(),
            signature: lease.signature.clone(),
            key_id: lease.key_id.clone(),
        };
        let verifying = match (&key_set, lease.key_id.as_str()) {
            (Some(set), key_id) if !key_id.is_empty() => {
                let key = set
                    .verifying_key_for(key_id)
                    .map_err(|e| AgentError::Message(e.to_string()))?;
                Some(key)
            }
            (Some(set), _) => {
                let (_, key) = set
                    .active_key()
                    .map_err(|e| AgentError::Message(e.to_string()))?;
                Some(key)
            }
            (None, key_id) if !key_id.is_empty() => {
                let hex_key = public_key_hex_for_key_id(key_set_path, key_id)?;
                let key = issuer_verifying_key(&hex_key)
                    .map_err(|e| AgentError::Message(e.to_string()))?;
                Some(key)
            }
            (None, _) => None,
        };
        match verifying {
            Some(key) => store
                .record(&signed, &key, now)
                .map_err(|e| AgentError::Message(format!("lease record: {e}")))?,
            None => {
                return Err(AgentError::Message(
                    "no pinned issuer key available to verify the lease".into(),
                ))
            }
        }
    }
    Ok(store.high_water_revocation_epoch())
}

/// Look up the public key hex for a key_id in the persisted key-set file.
fn public_key_hex_for_key_id(key_set_path: &Path, key_id: &str) -> Result<String, AgentError> {
    let set = IssuerKeySet::load(key_set_path)?;
    let pinned = set
        .keys
        .iter()
        .find(|k| k.key_id == key_id)
        .ok_or_else(|| AgentError::Message(format!("unknown key_id {key_id}")))?;
    Ok(pinned.public_key_hex.clone())
}

/// Persist bytes atomically: sibling temp file + rename (plan §12.3).
pub(crate) fn persist_atomically(path: &Path, bytes: &[u8]) -> Result<(), AgentError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Digest helper exposed for tests: key_id = SHA-256 of the raw public key.
pub fn key_id_of_public_key(public_key: &ed25519_dalek::VerifyingKey) -> String {
    hex::encode(sha2::Sha256::digest(public_key.as_bytes()))
}

/// Pick the newest unexpired lease from a store: Login first (the P0
/// consumer path), then the other operations.
pub fn active_lease_in(store: &Store, now: u64) -> Option<oma_id_agent_core::VerifiedLease<'_>> {
    use oma_id_agent_core::Operation as CoreOperation;
    store
        .active_lease(now, CoreOperation::Login)
        .or_else(|| store.active_lease(now, CoreOperation::Unlock))
        .or_else(|| store.active_lease(now, CoreOperation::Elevate))
        .or_else(|| store.active_lease(now, CoreOperation::RemoteLogin))
}
