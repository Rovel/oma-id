//! Consumer-side proof for the thin PAM client against the fake root-owned
//! service: explicit pass, explicit denial, daemon-down, timeout and protocol
//! violation all resolve to the fail-closed [`Outcome`] the PAM layer needs.

use oma_id_agent_core::{Operation as CoreOperation, VerifiedLease};
use oma_id_agent_daemon::serve;
use oma_id_agent_ipc::{read_message, write_message, AgentRequest, PROTOCOL_VERSION};
use oma_id_pam_client::{Client, Outcome, UnavailableReason, DEFAULT_TIMEOUT};
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
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
        "oma-id-pam-client-test-{}-{name}.sock",
        std::process::id()
    ));
    path
}

struct Harness {
    path: PathBuf,
}

/// Valid lease for the current user; the accept loop lives until process
/// exit and each harness uses a unique socket name.
fn start_service(name: &str) -> Harness {
    start_service_with_credential(name, None)
}

fn start_service_with_credential(
    name: &str,
    expected_credential: Option<&'static str>,
) -> Harness {
    let path = socket_path(name);
    let _ = std::fs::remove_file(&path);
    let ops: &[CoreOperation] = &[CoreOperation::Unlock, CoreOperation::Login];
    let lease = VerifiedLease {
        subject_id: "person-1",
        device_id: "device-1",
        not_before: now() - 60,
        expires_at: now() + 3_600,
        revocation_epoch: 1,
        operations: ops,
    };
    let thread_path = path.clone();
    std::thread::spawn(move || {
        let config = oma_id_agent_daemon::ServiceConfig {
            socket_path: &thread_path,
            lease,
            trusted_time_floor: now() - 60,
            minimum_revocation_epoch: 1,
            expected_credential,
        };
        serve(&config).expect("service loop");
    });
    wait_for_socket(&path);
    Harness { path }
}

fn wait_for_socket(path: &std::path::Path) {
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

#[test]
fn authorized_when_agent_allows() {
    let service = start_service("allow");
    let client = Client::new(&service.path, DEFAULT_TIMEOUT);
    assert_eq!(
        client.authorize(
            oma_id_agent_ipc::Consumer::Quickshell,
            oma_id_agent_ipc::Operation::Unlock,
            &current_username()
        ),
        Outcome::Authorized
    );
}

#[test]
fn explicit_denial_is_denied_not_unavailable() {
    let service = start_service("deny");
    let client = Client::new(&service.path, DEFAULT_TIMEOUT);
    // Quickshell may only ask for Unlock, for any peer: the agent answers
    // an explicit denial, which the PAM layer reports differently from a
    // dead agent. (Sddm/Login would be environment-dependent: denied by
    // peer policy for non-root peers but allowed for root under this
    // lease, so it cannot anchor the assertion.)
    assert_eq!(
        client.authorize(
            oma_id_agent_ipc::Consumer::Quickshell,
            oma_id_agent_ipc::Operation::Login,
            &current_username()
        ),
        Outcome::Denied
    );
}

#[test]
fn daemon_down_fails_closed() {
    let path = socket_path("down");
    let _ = std::fs::remove_file(&path);
    let client = Client::new(&path, DEFAULT_TIMEOUT);
    assert_eq!(
        client.authorize(
            oma_id_agent_ipc::Consumer::Quickshell,
            oma_id_agent_ipc::Operation::Unlock,
            &current_username()
        ),
        Outcome::Unavailable(UnavailableReason::ConnectFailed)
    );
}

#[test]
fn unresponsive_agent_times_out() {
    let path = socket_path("silent");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            std::thread::sleep(Duration::from_millis(500));
            drop(stream);
        }
    });
    wait_for_socket(&path);
    let client = Client::new(&path, Duration::from_millis(100));
    assert_eq!(
        client.authorize(
            oma_id_agent_ipc::Consumer::Quickshell,
            oma_id_agent_ipc::Operation::Unlock,
            &current_username()
        ),
        Outcome::Unavailable(UnavailableReason::TimedOut)
    );
}

#[test]
fn lying_agent_protocol_violation_fails_closed() {
    // An agent that answers with the wrong correlation id must not be treated
    // as a decision.
    let path = socket_path("lying");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let request: AgentRequest = match read_message(&mut stream) {
                Ok(request) => request,
                Err(_) => return,
            };
            let request_id = match &request {
                AgentRequest::Authorization(inner) => inner.request_id,
                AgentRequest::CredentialExchange(inner) => inner.request_id,
            };
            let mut response = oma_id_agent_ipc::AgentResponse {
                version: PROTOCOL_VERSION,
                request_id,
                decision: oma_id_agent_ipc::Decision::Allow,
            };
            response.request_id = [99; 16];
            let _ = write_message(&mut stream, &response);
        }
    });
    wait_for_socket(&path);
    let client = Client::new(&path, DEFAULT_TIMEOUT);
    assert_eq!(
        client.authorize(
            oma_id_agent_ipc::Consumer::Quickshell,
            oma_id_agent_ipc::Operation::Unlock,
            &current_username()
        ),
        Outcome::Unavailable(UnavailableReason::ProtocolViolation)
    );

    // And an agent that answers with garbage bytes is equally unusable.
    let path = socket_path("garbage");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let body = b"not a decision";
            let _ = stream.write_all(&(body.len() as u32).to_be_bytes());
            let _ = stream.write_all(body);
        }
    });
    wait_for_socket(&path);
    let client = Client::new(&path, DEFAULT_TIMEOUT);
    assert_eq!(
        client.authorize(
            oma_id_agent_ipc::Consumer::Quickshell,
            oma_id_agent_ipc::Operation::Unlock,
            &current_username()
        ),
        Outcome::Unavailable(UnavailableReason::ProtocolViolation)
    );
}

#[test]
fn exchange_credential_authorized_when_agent_allows() {
    let service = start_service_with_credential("cred-allow", Some("p1nned-credential"));
    let client = Client::new(&service.path, DEFAULT_TIMEOUT);
    assert_eq!(
        client.exchange_credential(
            oma_id_agent_ipc::Consumer::Quickshell,
            oma_id_agent_ipc::Operation::Unlock,
            &current_username(),
            "p1nned-credential"
        ),
        Outcome::Authorized
    );
}

#[test]
fn exchange_credential_denied_is_denied_not_unavailable() {
    let service = start_service_with_credential("cred-deny", Some("p1nned-credential"));
    let client = Client::new(&service.path, DEFAULT_TIMEOUT);
    // Wrong material is an explicit denial.
    assert_eq!(
        client.exchange_credential(
            oma_id_agent_ipc::Consumer::Quickshell,
            oma_id_agent_ipc::Operation::Unlock,
            &current_username(),
            "not-the-credential"
        ),
        Outcome::Denied
    );
    // No credential configured at all: same Denied, never Unavailable.
    let unconfigured = start_service("cred-unconfigured");
    let client = Client::new(&unconfigured.path, DEFAULT_TIMEOUT);
    assert_eq!(
        client.exchange_credential(
            oma_id_agent_ipc::Consumer::Quickshell,
            oma_id_agent_ipc::Operation::Unlock,
            &current_username(),
            "p1nned-credential"
        ),
        Outcome::Denied
    );
}

#[test]
fn exchange_credential_fails_closed_when_daemon_down() {
    let path = socket_path("cred-down");
    let _ = std::fs::remove_file(&path);
    let client = Client::new(&path, DEFAULT_TIMEOUT);
    assert_eq!(
        client.exchange_credential(
            oma_id_agent_ipc::Consumer::Quickshell,
            oma_id_agent_ipc::Operation::Unlock,
            &current_username(),
            "p1nned-credential"
        ),
        Outcome::Unavailable(UnavailableReason::ConnectFailed)
    );
}

#[test]
fn unusable_pam_username_fails_closed_before_connecting() {
    // Point at a path with no daemon: the result must be ProtocolViolation
    // (request rejected locally), not ConnectFailed, proving the client never
    // sends an unsafe username onto the wire.
    let path = socket_path("never-connected");
    let _ = std::fs::remove_file(&path);
    let client = Client::new(&path, DEFAULT_TIMEOUT);
    assert_eq!(
        client.authorize(
            oma_id_agent_ipc::Consumer::Quickshell,
            oma_id_agent_ipc::Operation::Unlock,
            "Owner"
        ),
        Outcome::Unavailable(UnavailableReason::ProtocolViolation)
    );
}
