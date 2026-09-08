//! Signed-lease trust-chain demonstration for the fake agent: a lease is
//! signed by an issuer key, recorded in the store (signature verification +
//! revocation-epoch high-water mark at record time), re-verified wholesale on
//! load, selected for the service, and consumed by the real socket
//! authorization path. This is the P0 groundwork for the trust chain — the
//! fake agent stops trusting command-line lease arguments when a store is
//! supplied. A tampered store file must fail closed.

#![cfg(target_os = "linux")]

use oma_id_agent_core::Operation as CoreOperation;
use oma_id_agent_daemon::{bind, handle_connection, ServiceConfig};
use oma_id_agent_ipc::{
    read_message, write_message, AgentRequest, AgentResponse, AuthorizationRequest, Consumer,
    Decision, Operation, PROTOCOL_VERSION,
};
use oma_id_agent_store::{issuer_keypair, LeasePayload, SignedLease, Store};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Resolve the username from the calling UID (authoritative mapping, never
/// $USER — see the socket_service harness note).
fn current_username() -> String {
    use std::ffi::CStr;
    let uid = unsafe { libc::getuid() };
    unsafe {
        let pwd = libc::getpwuid(uid);
        if pwd.is_null() {
            panic!("no passwd entry for uid {uid}");
        }
        CStr::from_ptr((*pwd).pw_name).to_string_lossy().into_owned()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs()
}

fn socket_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "oma-id-store-test-{}-{name}.sock",
        std::process::id()
    ));
    path
}

fn wait_for_socket(path: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "socket {} never appeared",
            path.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn signed_lease_store_authorizes_through_the_socket_path() {
    let current = now();
    let dir = tempfile::tempdir().expect("tempdir");
    let store_path = dir.path().join("leases.json");
    let (issuer, verifying) = issuer_keypair(&[9u8; 32]).expect("keypair");

    // The issuer signs; the agent records (signature + HWM checks at record
    // time) and persists atomically.
    let mut store = Store::load(&store_path).expect("empty store");
    let payload = LeasePayload {
        subject_id: "person-1".into(),
        device_id: "device-1".into(),
        not_before: current - 60,
        expires_at: current + 3_600,
        revocation_epoch: 7,
        operations: vec![CoreOperation::Login, CoreOperation::Unlock],
    };
    store
        .record(&SignedLease::sign(payload, &issuer), &verifying, current)
        .expect("record signed lease");

    // The agent loads the store, re-verifies every signature against the
    // pinned key, and selects the active lease for the service.
    let loaded = Store::load(&store_path).expect("reload");
    loaded.verify_all(&verifying).expect("signatures valid");
    let lease = loaded
        .active_lease(current, CoreOperation::Login)
        .expect("active signed lease");
    let lease_floor = lease.not_before;

    // The real socket path authorizes a bound request backed by the signed
    // lease only — no CLI lease arguments exist in this mode.
    let path = socket_path("signed-allow");
    let _ = std::fs::remove_file(&path);
    let listener = bind(&path).expect("bind");
    wait_for_socket(&path);

    // The consumer side runs first and holds its request in the socket
    // buffer; the service then handles it synchronously (the accept-loop
    // variant blocks forever, so this test drives one connection by hand).
    let mut client = UnixStream::connect(&path).expect("connect");
    // Non-root peer policy allows only Quickshell/Unlock with a uid-matched
    // local account; use the caller's own resolved username (never $USER).
    let request = AuthorizationRequest {
        version: PROTOCOL_VERSION,
        request_id: [9; 16],
        local_username: current_username(),
        consumer: Consumer::Quickshell,
        operation: Operation::Unlock,
    };
    write_message(&mut client, &AgentRequest::Authorization(request)).expect("write request");

    let (mut server_stream, _) = listener.accept().expect("accept");
    let config = ServiceConfig {
        socket_path: &path,
        lease,
        trusted_time_floor: lease_floor,
        minimum_revocation_epoch: loaded.high_water_revocation_epoch(),
        expected_credential: None,
    };
    handle_connection(&mut server_stream, &config);

    let response: AgentResponse = read_message(&mut client).expect("read response");
    match response.decision {
        Decision::Allow => {}
        other => panic!("expected Allow backed by the signed lease, got {other:?}"),
    }
    drop(client);
    drop(listener);
}

#[test]
fn tampered_store_file_fails_verification() {
    let current = now();
    let dir = tempfile::tempdir().expect("tempdir");
    let store_path = dir.path().join("leases.json");
    let (issuer, verifying) = issuer_keypair(&[10u8; 32]).expect("keypair");

    let mut store = Store::load(&store_path).expect("empty store");
    let payload = LeasePayload {
        subject_id: "person-1".into(),
        device_id: "device-1".into(),
        not_before: current - 60,
        expires_at: current + 3_600,
        revocation_epoch: 7,
        operations: vec![CoreOperation::Login],
    };
    store
        .record(&SignedLease::sign(payload, &issuer), &verifying, current)
        .expect("record");

    // Simulate an attacker editing the store file: bump the revocation
    // epoch in the JSON. The file stays valid JSON, so load() alone must
    // not be trusted — signature verification catches this.
    let text = std::fs::read_to_string(&store_path).expect("read store");
    let tampered = text.replace("\"revocation_epoch\": 7", "\"revocation_epoch\": 99");
    assert_ne!(text, tampered, "tamper simulation must change the file");
    std::fs::write(&store_path, tampered).expect("write tampered store");

    let reloaded = Store::load(&store_path).expect("tampered file still parses");
    assert!(
        reloaded.verify_all(&verifying).is_err(),
        "tampered store must fail signature verification (fail closed)"
    );
}
