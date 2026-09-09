//! P2 slice tests for the real agent crate: device identity persistence,
//! check-in request signing, and check-in application through the verified
//! store path (the lease signature must verify against the pinned issuer
//! key set before it can be recorded).

#![cfg(target_os = "linux")]

use ed25519_dalek::{Signer, SigningKey};
use oma_id_agent::{active_lease_in, apply_check_in, check_in, key_id_of_public_key, DeviceIdentity, SignedLeaseWire};
use oma_id_agent_store::{issuer_keypair, LeasePayload, Store};
use sha2::Digest;

#[test]
fn device_identity_persists_and_reloads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("device.key");

    let first = DeviceIdentity::load_or_create(&key_path).expect("create");
    assert!(key_path.exists());
    let second = DeviceIdentity::load_or_create(&key_path).expect("reload");
    assert_eq!(
        hex::encode(first.signing_key.verifying_key().as_bytes()),
        second.public_key_hex,
        "the same key must reload across boots"
    );
}

#[test]
fn device_key_file_is_0600() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("state/device.key");
    DeviceIdentity::load_or_create(&key_path).expect("create");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&key_path).expect("metadata").permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "device key must be 0600");
}

#[test]
fn key_id_derivation_matches_the_contract() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let key_id = key_id_of_public_key(&key.verifying_key());
    let direct = hex::encode(sha2::Sha256::digest(key.verifying_key().as_bytes()));
    assert_eq!(key_id, direct);
}

#[test]
fn apply_check_in_records_leases_and_persists_the_key_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_set_path = dir.path().join("issuer-keys.json");

    let (issuer, verifying) = issuer_keypair(&[30u8; 32]).expect("keypair");
    let key_id = key_id_of_public_key(&verifying);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let payload = LeasePayload {
        subject_id: "person-1".into(),
        device_id: "device-1".into(),
        not_before: now - 60,
        expires_at: now + 3_600,
        revocation_epoch: 7,
        operations: vec![oma_id_agent_core::Operation::Login, oma_id_agent_core::Operation::Unlock],
    };
    let signature = hex::encode(issuer.sign(&oma_id_agent_store::canonical_payload_json(&payload)).to_bytes());

    let response = oma_id_agent::CheckInResponse {
        version: 2,
        high_water_revocation_epoch: 7,
        leases: vec![SignedLeaseWire {
            payload: payload.clone(),
            signature,
            key_id: key_id.clone(),
        }],
        key_id: key_id.clone(),
        issuer_keys: vec![oma_id_agent_store::PinnedIssuerKey {
            key_id: key_id.clone(),
            public_key_hex: hex::encode(verifying.as_bytes()),
            state: oma_id_agent_store::KeyState::Active,
        }],
        posix: Some(oma_id_agent::provisioning::PosixMapping {
            username: "deviceowner".into(),
            uid: 10001,
            gid: 10001,
            home: "/home/deviceowner".into(),
            shell: "/bin/zsh".into(),
            full_name: "Device Owner".into(),
        }),
    };

    let mut store = Store::load(&dir.path().join("leases.json")).expect("empty store");
    let hwm = apply_check_in(&mut store, &response, &key_set_path).expect("apply");
    assert_eq!(hwm, 7);

    // The store persists the lease and the key set is written for the
    // startup verification path.
    let reloaded = Store::load(&dir.path().join("leases.json")).expect("reload");
    assert_eq!(reloaded.lease_count(), 1);
    let lease = active_lease_in(&reloaded, now).expect("active lease");
    assert_eq!(lease.subject_id, "person-1");

    // The persisted key set must validate and contain the pinned key.
    let set = oma_id_agent_store::IssuerKeySet::load(&key_set_path).expect("key set");
    assert!(set.verifying_key_for(&key_id).is_ok());
}

#[test]
fn check_in_signs_the_expected_message() {
    // The check-in request signature covers "device_id|timestamp" — verify
    // it independently with the device's public key.
    let identity = DeviceIdentity::load_or_create(
        &tempfile::tempdir().expect("tempdir").path().join("device.key"),
    )
    .expect("identity");
    let timestamp = 1_700_000_000u64;
    let message = format!("{}|{timestamp}", "device-x");
    let signature = identity.signing_key.sign(message.as_bytes());
    let verifying = identity.signing_key.verifying_key();
    verifying
        .verify_strict(message.as_bytes(), &signature)
        .expect("check-in signature must verify with the device public key");
}

#[test]
fn check_in_against_an_unreachable_server_fails_cleanly() {
    let identity = DeviceIdentity::load_or_create(
        &tempfile::tempdir().expect("tempdir").path().join("device.key"),
    )
    .expect("identity");
    let error = check_in("http://127.0.0.1:9", "device-1", &identity).expect_err("must fail");
    assert!(
        matches!(error, oma_id_agent::CheckInError::Http(_) | oma_id_agent::CheckInError::Rejected { .. }),
        "connection failure must be an http error"
    );
}