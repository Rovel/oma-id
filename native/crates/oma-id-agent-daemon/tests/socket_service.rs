//! Socket-level proof for the fake root-owned service and unprivileged
//! client: happy path, peer identity, malformed messages, daemon-down and
//! timeout behavior, and lease-decision mapping. The service runs as the
//! current (non-root) test user, so these tests exercise the fail-closed
//! non-root side of the peer policy; root behavior is covered by unit tests
//! in `oma-id-agent-ipc`.

use oma_id_agent_core::{Operation as CoreOperation, VerifiedLease};
use oma_id_agent_daemon::{bind, handle_connection, serve, ServiceConfig};
use oma_id_agent_ipc::{
    read_message, write_message, AgentRequest, AgentResponse, AuthorizationRequest, Consumer,
    Credential, CredentialExchangeRequest, Decision, DenialCode, Operation, PROTOCOL_VERSION,
    MAX_CREDENTIAL_BYTES, MAX_MESSAGE_BYTES,
};
use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs()
}

fn socket_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "oma-id-daemon-test-{}-{name}.sock",
        std::process::id()
    ));
    path
}

struct Bounds {
    not_before: u64,
    expires_at: u64,
    trusted_time_floor: u64,
    revocation_epoch: u64,
    minimum_revocation_epoch: u64,
}

impl Bounds {
    fn valid_around(current: u64) -> Self {
        Self {
            not_before: current - 60,
            expires_at: current + 3_600,
            trusted_time_floor: current - 60,
            revocation_epoch: 1,
            minimum_revocation_epoch: 1,
        }
    }

    fn expired(current: u64) -> Self {
        Self {
            not_before: current - 120,
            expires_at: current - 1,
            trusted_time_floor: current - 120,
            revocation_epoch: 1,
            minimum_revocation_epoch: 1,
        }
    }

    fn rolled_back_clock(current: u64) -> Self {
        Self {
            not_before: current - 3_600,
            expires_at: current + 3_600,
            trusted_time_floor: current + 3_600,
            revocation_epoch: 1,
            minimum_revocation_epoch: 1,
        }
    }

    fn stale_revocation_epoch(current: u64) -> Self {
        Self {
            not_before: current - 60,
            expires_at: current + 3_600,
            trusted_time_floor: current - 60,
            revocation_epoch: 1,
            minimum_revocation_epoch: 2,
        }
    }
}

/// The accept loop runs until the test process exits; each harness uses a
/// unique socket name, so leftover loops are inert. The handle is dropped on
/// purpose rather than joined.
struct Harness {
    path: PathBuf,
}

fn start_service(name: &str, bounds: Bounds) -> Harness {
    start_service_with_credential(name, bounds, None)
}

fn start_service_with_credential(
    name: &str,
    bounds: Bounds,
    expected_credential: Option<&'static str>,
) -> Harness {
    let path = socket_path(name);
    let _ = std::fs::remove_file(&path);
    let ops: &[CoreOperation] = &[CoreOperation::Unlock];
    let lease = VerifiedLease {
        subject_id: "person-1",
        device_id: "device-1",
        not_before: bounds.not_before,
        expires_at: bounds.expires_at,
        revocation_epoch: bounds.revocation_epoch,
        operations: ops,
    };
    let trusted_time_floor = bounds.trusted_time_floor;
    let minimum_revocation_epoch = bounds.minimum_revocation_epoch;
    let thread_path = path.clone();
    std::thread::spawn(move || {
        // The service thread owns the socket file for the process lifetime;
        // each test uses a unique name, so lingering accept loops are inert.
        let config = ServiceConfig {
            socket_path: &thread_path,
            lease,
            trusted_time_floor,
            minimum_revocation_epoch,
            expected_credential,
            bound_local_username: None,
            credential_verifier: None,
        };
        serve(&config).expect("service loop");
    });
    wait_for_socket(&path);
    Harness { path }
}

fn wait_for_socket(path: &Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "socket {} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Resolve the username from the calling UID. Deliberately not `$USER`:
/// environment variables are caller-influenced and unset in minimal
/// containers, while `getpwuid(getuid())` is the authoritative mapping.
fn current_username() -> String {
    use std::ffi::CStr;
    let uid = unsafe { libc::getuid() };
    let mut buffer = vec![0_u8; 4096];
    let mut entry = MaybeUninit::<libc::passwd>::uninit();
    loop {
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: same contract as the daemon's `local_user_uid` lookup.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast::<libc::c_char>(),
                buffer.len(),
                &mut found,
            )
        };
        if status == libc::ERANGE {
            let next = buffer.len().saturating_mul(2).max(8196);
            buffer.resize(next, 0);
            continue;
        }
        assert_eq!(status, 0, "getpwuid_r failed");
        assert!(!found.is_null(), "no passwd entry for uid {uid}");
        // SAFETY: lookup succeeded; `found` aliases our storage.
        let entry = unsafe { &*found };
        let name = unsafe { CStr::from_ptr(entry.pw_name) };
        return name.to_str().expect("non-UTF8 username").to_string();
    }
}

fn request(consumer: Consumer, operation: Operation) -> AuthorizationRequest {
    AuthorizationRequest {
        version: PROTOCOL_VERSION,
        request_id: [9; 16],
        local_username: current_username(),
        consumer,
        operation,
    }
}

fn credential_request(
    consumer: Consumer,
    operation: Operation,
    password: &str,
) -> CredentialExchangeRequest {
    CredentialExchangeRequest {
        version: PROTOCOL_VERSION,
        request_id: [11; 16],
        local_username: current_username(),
        consumer,
        operation,
        credential: Credential::Password(password.to_owned()),
    }
}

#[test]
fn allows_same_user_quickshell_unlock() {
    let service = start_service("allow", Bounds::valid_around(now()));
    let response = oma_id_agent_ipc::exchange_authorization(
        &service.path,
        &request(Consumer::Quickshell, Operation::Unlock),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(response.decision, Decision::Allow);
}

#[test]
fn denies_unprivileged_consumer_for_non_root_peer() {
    let service = start_service("peer", Bounds::valid_around(now()));
    if unsafe { libc::geteuid() } == 0 {
        // Root peer (container): Sddm/Login passes the peer policy but is
        // still denied because the harness lease only scopes Unlock —
        // defense in depth, and the opaque code shows the client cannot
        // tell which layer fired.
        let response = oma_id_agent_ipc::exchange_authorization(
            &service.path,
            &request(Consumer::Sddm, Operation::Login),
            Duration::from_secs(2),
        )
        .expect("exchange");
        assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));
    } else {
        // Sddm/Login is a valid root pair, but this peer is not root.
        let response = oma_id_agent_ipc::exchange_authorization(
            &service.path,
            &request(Consumer::Sddm, Operation::Login),
            Duration::from_secs(2),
        )
        .expect("exchange");
        assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));
    }

    // Quickshell may only ask for Unlock.
    let response = oma_id_agent_ipc::exchange_authorization(
        &service.path,
        &request(Consumer::Quickshell, Operation::Login),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));
}

#[test]
fn denies_unknown_local_account_opaquely() {
    let service = start_service("unknown-user", Bounds::valid_around(now()));
    let mut candidate = request(Consumer::Quickshell, Operation::Unlock);
    candidate.local_username = "definitely-not-an-oma-user".to_owned();
    let response = oma_id_agent_ipc::exchange_authorization(&service.path, &candidate, Duration::from_secs(2))
        .expect("exchange");
    assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));
}

#[test]
fn maps_lease_denials_to_opaque_not_authorized() {
    let expired = start_service("expired", Bounds::expired(now()));
    let response = oma_id_agent_ipc::exchange_authorization(
        &expired.path,
        &request(Consumer::Quickshell, Operation::Unlock),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));

    let rolled_back = start_service("rollback", Bounds::rolled_back_clock(now()));
    let response = oma_id_agent_ipc::exchange_authorization(
        &rolled_back.path,
        &request(Consumer::Quickshell, Operation::Unlock),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));

    let stale = start_service("stale-epoch", Bounds::stale_revocation_epoch(now()));
    let response = oma_id_agent_ipc::exchange_authorization(
        &stale.path,
        &request(Consumer::Quickshell, Operation::Unlock),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));

    // Elevate is not in the lease's operation set.
    let valid = start_service("op-scope", Bounds::valid_around(now()));
    let response = oma_id_agent_ipc::exchange_authorization(
        &valid.path,
        &request(Consumer::Quickshell, Operation::Elevate),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));
}

#[test]
fn malformed_frames_close_without_response() {
    let service = start_service("malformed", Bounds::valid_around(now()));

    // Garbage JSON with a well-formed length prefix.
    let mut stream = UnixStream::connect(&service.path).expect("connect");
    let body = b"this is not json {{{";
    write_message_raw(&mut stream, body);
    let error = read_message::<AgentResponse>(&mut stream)
        .expect_err("must not get a response");
    assert!(matches!(
        error,
        oma_id_agent_ipc::ProtocolError::Io(ref io_error)
            if matches!(io_error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset)
    ));

    // Oversized length prefix: the service must refuse before allocating.
    let mut stream = UnixStream::connect(&service.path).expect("connect");
    let oversized = (MAX_MESSAGE_BYTES as u32 + 1).to_be_bytes();
    stream.write_all(&oversized).expect("write prefix");
    let error = read_message::<AgentResponse>(&mut stream)
        .expect_err("must not get a response");
    assert!(matches!(
        error,
        oma_id_agent_ipc::ProtocolError::Io(ref io_error)
            if matches!(io_error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset)
    ));
}

#[test]
fn validation_failures_return_correlated_invalid_request() {
    let service = start_service("invalid", Bounds::valid_around(now()));

    // Unsupported version: body parses, so the reply must correlate.
    let mut stream = UnixStream::connect(&service.path).expect("connect");
    let mut bad_version = request(Consumer::Quickshell, Operation::Unlock);
    bad_version.version = PROTOCOL_VERSION + 1;
    let expected_id = bad_version.request_id;
    write_message(&mut stream, &AgentRequest::Authorization(bad_version)).expect("write");
    let response: AgentResponse = read_message(&mut stream).expect("response");
    assert_eq!(response.decision, Decision::Deny(DenialCode::InvalidRequest));
    assert_eq!(response.request_id, expected_id);

    // Unsafe local username.
    let mut stream = UnixStream::connect(&service.path).expect("connect");
    let mut bad_name = request(Consumer::Quickshell, Operation::Unlock);
    bad_name.local_username = "Owner".to_owned();
    let expected_id = bad_name.request_id;
    write_message(&mut stream, &AgentRequest::Authorization(bad_name)).expect("write");
    let response: AgentResponse = read_message(&mut stream).expect("response");
    assert_eq!(response.decision, Decision::Deny(DenialCode::InvalidRequest));
    assert_eq!(response.request_id, expected_id);

    // An untagged v1-style frame has no correlation id the daemon can trust:
    // it must close without a response.
    let mut stream = UnixStream::connect(&service.path).expect("connect");
    let body = serde_json::to_vec(&request(Consumer::Quickshell, Operation::Unlock)).expect("json");
    write_message_raw(&mut stream, &body);
    let error = read_message::<AgentResponse>(&mut stream)
        .expect_err("must not get a response");
    assert!(matches!(
        error,
        oma_id_agent_ipc::ProtocolError::Io(ref io_error)
            if matches!(io_error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset)
    ));
}

#[test]
fn daemon_down_fails_closed() {
    let path = socket_path("missing-daemon");
    let _ = std::fs::remove_file(&path);
    let error = oma_id_agent_ipc::exchange_authorization(
        &path,
        &request(Consumer::Quickshell, Operation::Unlock),
        Duration::from_millis(200),
    )
    .expect_err("must fail closed");
    assert!(matches!(error, oma_id_agent_ipc::ProtocolError::Io(_)));
}

#[test]
fn unresponsive_daemon_times_out() {
    let path = socket_path("unresponsive");
    let _ = std::fs::remove_file(&path);
    let listener = bind(&path).expect("bind");
    // Accept and hold the connection without answering.
    let holder = std::thread::spawn(move || {
        if let Ok(stream) = listener.accept() {
            std::thread::sleep(Duration::from_millis(500));
            drop(stream);
        }
    });
    wait_for_socket(&path);
    let error = oma_id_agent_ipc::exchange_authorization(
        &path,
        &request(Consumer::Quickshell, Operation::Unlock),
        Duration::from_millis(100),
    )
    .expect_err("must time out");
    assert!(matches!(
        error,
        oma_id_agent_ipc::ProtocolError::Io(ref io_error)
            if matches!(io_error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
    ));
    holder.join().expect("holder thread");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn single_connection_handler_serves_one_exchange() {
    // Drive handle_connection directly to pin its contract without the loop.
    let (mut service, mut client) = UnixStream::pair().expect("socket pair");
    let path = socket_path("direct");
    let ops: &[CoreOperation] = &[CoreOperation::Unlock];
    let lease = VerifiedLease {
        subject_id: "person-1",
        device_id: "device-1",
        not_before: now() - 60,
        expires_at: now() + 3_600,
        revocation_epoch: 1,
        operations: ops,
    };
    let worker = std::thread::spawn(move || {
        let config = ServiceConfig {
            socket_path: &path,
            lease,
            trusted_time_floor: now() - 60,
            minimum_revocation_epoch: 1,
            expected_credential: None,
            bound_local_username: None,
            credential_verifier: None,
        };
        handle_connection(&mut service, &config);
    });
    write_message(
        &mut client,
        &AgentRequest::Authorization(request(Consumer::Quickshell, Operation::Unlock)),
    )
    .expect("write");
    let response: AgentResponse = read_message(&mut client).expect("response");
    assert_eq!(response.decision, Decision::Allow);
    worker.join().expect("handler thread");
}

#[test]
fn credential_exchange_allows_the_pinned_credential() {
    let service = start_service_with_credential(
        "cred-allow",
        Bounds::valid_around(now()),
        Some("p1nned-credential"),
    );
    let response = oma_id_agent_ipc::exchange_credential(
        &service.path,
        &credential_request(Consumer::Quickshell, Operation::Unlock, "p1nned-credential"),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(response.decision, Decision::Allow);
}

#[test]
fn credential_exchange_denials_are_opaque() {
    let pinned = start_service_with_credential(
        "cred-wrong",
        Bounds::valid_around(now()),
        Some("p1nned-credential"),
    );
    // Wrong password.
    let response = oma_id_agent_ipc::exchange_credential(
        &pinned.path,
        &credential_request(Consumer::Quickshell, Operation::Unlock, "not-the-credential"),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));

    // Empty password.
    let response = oma_id_agent_ipc::exchange_credential(
        &pinned.path,
        &credential_request(Consumer::Quickshell, Operation::Unlock, ""),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));

    // No credential configured at all: indistinguishable from a wrong one.
    let unconfigured = start_service("cred-unconfigured", Bounds::valid_around(now()));
    let response = oma_id_agent_ipc::exchange_credential(
        &unconfigured.path,
        &credential_request(Consumer::Quickshell, Operation::Unlock, "p1nned-credential"),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));
}

#[test]
fn credential_exchange_enforces_peer_policy_and_request_validation() {
    let service = start_service_with_credential(
        "cred-policy",
        Bounds::valid_around(now()),
        Some("p1nned-credential"),
    );

    // Quickshell may only ask for Unlock, for any peer: invalid pair is an
    // opaque denial, not a protocol answer.
    let response = oma_id_agent_ipc::exchange_credential(
        &service.path,
        &credential_request(Consumer::Quickshell, Operation::Login, "p1nned-credential"),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));

    // Unknown local account: denied like any other failure (no oracle).
    let mut unknown = credential_request(
        Consumer::Quickshell,
        Operation::Unlock,
        "p1nned-credential",
    );
    unknown.local_username = "definitely-not-an-oma-user".to_owned();
    let response = oma_id_agent_ipc::exchange_credential(
        &service.path,
        &unknown,
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(response.decision, Decision::Deny(DenialCode::NotAuthorized));

    // Oversized credential: structural failure, so the one non-opaque code.
    let oversized = credential_request(
        Consumer::Quickshell,
        Operation::Unlock,
        &"x".repeat(MAX_CREDENTIAL_BYTES + 1),
    );
    let expected_id = oversized.request_id;
    let mut stream = UnixStream::connect(&service.path).expect("connect");
    write_message(&mut stream, &AgentRequest::CredentialExchange(oversized)).expect("write");
    let response: AgentResponse = read_message(&mut stream).expect("response");
    assert_eq!(response.decision, Decision::Deny(DenialCode::InvalidRequest));
    assert_eq!(response.request_id, expected_id);
}

#[test]
fn credential_exchange_is_independent_of_the_lease() {
    // Plan 9.1: a verified credential establishes the person, not the
    // permission. With an expired lease the credential exchange still
    // passes — and the authorization request on the same service is denied.
    let expired = start_service_with_credential(
        "cred-lease-sep",
        Bounds::expired(now()),
        Some("p1nned-credential"),
    );
    let credential = oma_id_agent_ipc::exchange_credential(
        &expired.path,
        &credential_request(Consumer::Quickshell, Operation::Unlock, "p1nned-credential"),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(credential.decision, Decision::Allow);

    let authorization = oma_id_agent_ipc::exchange_authorization(
        &expired.path,
        &request(Consumer::Quickshell, Operation::Unlock),
        Duration::from_secs(2),
    )
    .expect("exchange");
    assert_eq!(authorization.decision, Decision::Deny(DenialCode::NotAuthorized));
}

fn write_message_raw(writer: &mut impl Write, body: &[u8]) {
    writer
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|_| writer.write_all(body))
        .and_then(|_| writer.flush())
        .expect("raw frame");
}
