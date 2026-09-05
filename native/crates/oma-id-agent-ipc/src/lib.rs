//! Bounded local IPC types and framing for the OMA-ID PAM client and agent.
//!
//! Two request kinds share one wire format, tagged by `type` so a daemon can
//! never mistake one exchange for the other:
//!
//! - `authorization`: lease-decision request. Carries no credential material.
//! - `credential_exchange`: bounded, typed credential material forwarded by
//!   the PAM client. Verification happens in the agent; per the plan,
//!   authentication is separate from authorization and a verified credential
//!   never extends or overrides a lease.
//!
//! The only supported target is Linux, matching Omarchy.

#![cfg(target_os = "linux")]

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub const PROTOCOL_VERSION: u16 = 2;
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024;
pub const MAX_LOCAL_USERNAME_BYTES: usize = 32;
/// Upper bound for forwarded credential material. Production adds rate
/// limiting and breach defenses on top; the wire bound is structural.
pub const MAX_CREDENTIAL_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Consumer {
    Sddm,
    Quickshell,
    Tty,
    Sudo,
    Polkit,
    Ssh,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Login,
    Unlock,
    Elevate,
    RemoteLogin,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequest {
    pub version: u16,
    pub request_id: [u8; 16],
    pub local_username: String,
    pub consumer: Consumer,
    pub operation: Operation,
}

impl AuthorizationRequest {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if !valid_local_username(&self.local_username) {
            return Err(ProtocolError::InvalidLocalUsername);
        }
        Ok(())
    }
}

/// Credential material forwarded over the local socket. Typed, not an
/// opaque blob: the wire says what it is, and only bounded strings cross.
/// Fingerprint/biometric material never crosses this channel; those flows
/// are decided locally and only ask for authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Credential {
    Password(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialExchangeRequest {
    pub version: u16,
    pub request_id: [u8; 16],
    pub local_username: String,
    pub consumer: Consumer,
    pub operation: Operation,
    pub credential: Credential,
}

impl CredentialExchangeRequest {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if !valid_local_username(&self.local_username) {
            return Err(ProtocolError::InvalidLocalUsername);
        }
        let credential_bytes = match &self.credential {
            Credential::Password(password) => password.len(),
        };
        if credential_bytes > MAX_CREDENTIAL_BYTES {
            return Err(ProtocolError::CredentialTooLarge(credential_bytes));
        }
        Ok(())
    }
}

/// One request frame from the PAM client. The `type` tag is part of the
/// wire format (protocol v2): an untagged v1 frame fails to parse and the
/// connection closes without a response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentRequest {
    Authorization(AuthorizationRequest),
    CredentialExchange(CredentialExchangeRequest),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialCode {
    NotAuthorized,
    InvalidRequest,
    InternalFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "code", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny(DenialCode),
}

/// The agent's reply to either request kind. Correlation is by
/// `request_id`; the reply never echoes credential material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResponse {
    pub version: u16,
    pub request_id: [u8; 16],
    pub decision: Decision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerDenial {
    ConsumerOperationMismatch,
    UserMismatch,
    UnprivilegedConsumer,
}

/// Authorize the process hosting the PAM module, independently of the user's
/// credential and lease. `local_user_uid` must come from a trusted local account
/// lookup, never from the request body.
pub fn authorize_peer(
    peer: PeerCredentials,
    local_user_uid: u32,
    consumer: Consumer,
    operation: Operation,
) -> Result<(), PeerDenial> {
    if !consumer_supports_operation(consumer, operation) {
        return Err(PeerDenial::ConsumerOperationMismatch);
    }
    if peer.uid == 0 {
        return Ok(());
    }
    if consumer != Consumer::Quickshell || operation != Operation::Unlock {
        return Err(PeerDenial::UnprivilegedConsumer);
    }
    if peer.uid != local_user_uid {
        return Err(PeerDenial::UserMismatch);
    }
    Ok(())
}

fn consumer_supports_operation(consumer: Consumer, operation: Operation) -> bool {
    matches!(
        (consumer, operation),
        (Consumer::Sddm | Consumer::Tty, Operation::Login)
            | (Consumer::Quickshell, Operation::Unlock)
            | (Consumer::Sudo | Consumer::Polkit, Operation::Elevate)
            | (Consumer::Ssh, Operation::RemoteLogin)
    )
}

#[derive(Debug)]
pub enum ProtocolError {
    Io(io::Error),
    Json(serde_json::Error),
    EmptyMessage,
    MessageTooLarge(usize),
    UnsupportedVersion(u16),
    InvalidLocalUsername,
    CredentialTooLarge(usize),
    RequestIdMismatch,
}

impl From<io::Error> for ProtocolError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ProtocolError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub fn valid_local_username(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_LOCAL_USERNAME_BYTES
        && bytes[0] != b'-'
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(byte))
}

pub fn write_message<T: Serialize>(
    writer: &mut impl Write,
    value: &T,
) -> Result<(), ProtocolError> {
    let body = serde_json::to_vec(value)?;
    if body.is_empty() {
        return Err(ProtocolError::EmptyMessage);
    }
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge(body.len()));
    }
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

pub fn read_message<T: for<'de> Deserialize<'de>>(
    reader: &mut impl Read,
) -> Result<T, ProtocolError> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(ProtocolError::EmptyMessage);
    }
    if length > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge(length));
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}

/// Ask the agent for a lease decision. Validation failures (version,
/// username) happen locally, before anything is connected or sent.
pub fn exchange_authorization(
    socket_path: &Path,
    request: &AuthorizationRequest,
    timeout: Duration,
) -> Result<AgentResponse, ProtocolError> {
    request.validate()?;
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write_message(
        &mut stream,
        &AgentRequest::Authorization(request.clone()),
    )?;
    read_agent_response(&mut stream, request.request_id)
}

/// Forward bounded credential material to the agent for verification.
/// The client never decides: only an explicit `Allow` is a pass.
pub fn exchange_credential(
    socket_path: &Path,
    request: &CredentialExchangeRequest,
    timeout: Duration,
) -> Result<AgentResponse, ProtocolError> {
    request.validate()?;
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write_message(
        &mut stream,
        &AgentRequest::CredentialExchange(request.clone()),
    )?;
    read_agent_response(&mut stream, request.request_id)
}

fn read_agent_response(
    reader: &mut UnixStream,
    expected_request_id: [u8; 16],
) -> Result<AgentResponse, ProtocolError> {
    let response: AgentResponse = read_message(reader)?;
    if response.version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(response.version));
    }
    if response.request_id != expected_request_id {
        return Err(ProtocolError::RequestIdMismatch);
    }
    Ok(response)
}

pub fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    let mut raw = MaybeUninit::<libc::ucred>::uninit();
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `raw` points to writable storage for exactly `length` bytes, the
    // descriptor is borrowed from a live UnixStream, and the return code plus
    // returned length are checked before the value is assumed initialized.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            raw.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SO_PEERCRED size",
        ));
    }
    // SAFETY: getsockopt succeeded and returned the full ucred structure.
    let raw = unsafe { raw.assume_init() };
    Ok(PeerCredentials {
        pid: raw.pid,
        uid: raw.uid,
        gid: raw.gid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn request() -> AuthorizationRequest {
        AuthorizationRequest {
            version: PROTOCOL_VERSION,
            request_id: [7; 16],
            local_username: "oma_user-1".to_owned(),
            consumer: Consumer::Quickshell,
            operation: Operation::Unlock,
        }
    }

    #[test]
    fn round_trips_a_bounded_correlated_exchange() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let worker = thread::spawn(move || {
            let received: AgentRequest = read_message(&mut server).expect("request");
            match &received {
                AgentRequest::Authorization(request) => request.validate().expect("valid"),
                AgentRequest::CredentialExchange(_) => panic!("wrong request kind"),
            }
            write_message(
                &mut server,
                &AgentResponse {
                    version: PROTOCOL_VERSION,
                    request_id: [7; 16],
                    decision: Decision::Allow,
                },
            )
            .expect("response");
        });
        write_message(&mut client, &AgentRequest::Authorization(request()))
            .expect("write request");
        let response: AgentResponse = read_message(&mut client).expect("read response");
        assert_eq!(response.decision, Decision::Allow);
        assert_eq!(response.request_id, request().request_id);
        worker.join().expect("server worker");
    }

    #[test]
    fn credential_exchange_round_trips_and_rejects_unknown_tags() {
        let credential = CredentialExchangeRequest {
            version: PROTOCOL_VERSION,
            request_id: [8; 16],
            local_username: "oma_user-1".to_owned(),
            consumer: Consumer::Quickshell,
            operation: Operation::Unlock,
            credential: Credential::Password("s3cret".to_owned()),
        };
        credential.validate().expect("valid request");
        let frame = serde_json::to_vec(&AgentRequest::CredentialExchange(credential)).expect("json");
        let parsed: AgentRequest = serde_json::from_slice(&frame).expect("parse");
        assert!(matches!(
            parsed,
            AgentRequest::CredentialExchange(ref received)
                if received.credential == Credential::Password("s3cret".to_owned())
        ));

        // An untagged v1-style body and an unknown tag both fail to parse:
        // the daemon closes without a response rather than guess.
        let untagged = br#"{"version":2,"request_id":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"local_username":"u","consumer":"tty","operation":"login"}"#;
        assert!(serde_json::from_slice::<AgentRequest>(untagged).is_err());
        let unknown_tag = br#"{"type":"password","version":2}"#;
        assert!(serde_json::from_slice::<AgentRequest>(unknown_tag).is_err());
    }

    #[test]
    fn credential_requests_are_structurally_bounded() {
        const OVERSIZED: usize = MAX_CREDENTIAL_BYTES + 1;
        const NEXT_VERSION: u16 = PROTOCOL_VERSION + 1;
        let mut request = CredentialExchangeRequest {
            version: PROTOCOL_VERSION,
            request_id: [8; 16],
            local_username: "oma_user-1".to_owned(),
            consumer: Consumer::Quickshell,
            operation: Operation::Unlock,
            credential: Credential::Password("x".repeat(MAX_CREDENTIAL_BYTES)),
        };
        request.validate().expect("exactly at the bound is fine");

        request.credential = Credential::Password("x".repeat(OVERSIZED));
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::CredentialTooLarge(OVERSIZED))
        ));

        request.version = NEXT_VERSION;
        request.credential = Credential::Password("short".to_owned());
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::UnsupportedVersion(NEXT_VERSION))
        ));
    }

    #[test]
    fn rejects_oversized_frames_before_allocating_body() {
        let claimed = MAX_MESSAGE_BYTES + 1;
        let prefix = (claimed as u32).to_be_bytes();
        let mut bytes = prefix.as_slice();
        let error = read_message::<AuthorizationRequest>(&mut bytes).expect_err("oversized");
        assert!(matches!(error, ProtocolError::MessageTooLarge(size) if size == claimed));
    }

    #[test]
    fn rejects_unknown_fields_versions_and_unsafe_names() {
        let body = br#"{"type":"authorization","version":1,"request_id":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"local_username":"user","consumer":"tty","operation":"login","extra":true}"#;
        let mut frame = Vec::from((body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body);
        assert!(matches!(
            read_message::<AgentRequest>(&mut frame.as_slice()),
            Err(ProtocolError::Json(_))
        ));

        const NEXT_VERSION: u16 = PROTOCOL_VERSION + 1;
        let mut invalid = request();
        invalid.version = NEXT_VERSION;
        assert!(matches!(
            invalid.validate(),
            Err(ProtocolError::UnsupportedVersion(NEXT_VERSION))
        ));
        for name in [
            "",
            "-owner",
            "Owner",
            "user/name",
            "a_very_long_local_username_over_limit",
        ] {
            invalid = request();
            invalid.local_username = name.to_owned();
            assert!(matches!(
                invalid.validate(),
                Err(ProtocolError::InvalidLocalUsername)
            ));
        }
    }

    #[test]
    fn obtains_kernel_peer_credentials() {
        let (stream, _peer) = UnixStream::pair().expect("socket pair");
        let credentials = peer_credentials(&stream).expect("peer credentials");
        assert_eq!(credentials.pid, std::process::id() as i32);
        // SAFETY: getuid/getgid take no pointers and have no preconditions.
        assert_eq!(credentials.uid, unsafe { libc::getuid() });
        assert_eq!(credentials.gid, unsafe { libc::getgid() });
    }

    #[test]
    fn restricts_root_to_valid_consumer_operation_pairs() {
        let root = PeerCredentials {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        assert_eq!(
            authorize_peer(root, 1_000, Consumer::Sddm, Operation::Login),
            Ok(())
        );
        assert_eq!(
            authorize_peer(root, 1_000, Consumer::Sddm, Operation::Elevate),
            Err(PeerDenial::ConsumerOperationMismatch)
        );
    }

    #[test]
    fn permits_only_same_user_quickshell_unlock_for_non_root_peer() {
        let user = PeerCredentials {
            pid: 10,
            uid: 1_000,
            gid: 1_000,
        };
        assert_eq!(
            authorize_peer(user, 1_000, Consumer::Quickshell, Operation::Unlock),
            Ok(())
        );
        assert_eq!(
            authorize_peer(user, 1_001, Consumer::Quickshell, Operation::Unlock),
            Err(PeerDenial::UserMismatch)
        );
        assert_eq!(
            authorize_peer(user, 1_000, Consumer::Sddm, Operation::Login),
            Err(PeerDenial::UnprivilegedConsumer)
        );
        assert_eq!(
            authorize_peer(user, 1_000, Consumer::Quickshell, Operation::Login),
            Err(PeerDenial::ConsumerOperationMismatch)
        );
    }

    #[test]
    fn read_timeout_and_missing_daemon_fail_closed() {
        let (mut client, _server) = UnixStream::pair().expect("socket pair");
        client
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");
        let error = read_message::<AgentResponse>(&mut client).expect_err("must timeout");
        assert!(matches!(
            error,
            ProtocolError::Io(ref io_error)
                if matches!(io_error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
        ));

        let path =
            std::env::temp_dir().join(format!("oma-id-agent-{}-missing.sock", std::process::id()));
        assert!(matches!(
            exchange_authorization(&path, &request(), Duration::from_millis(20)),
            Err(ProtocolError::Io(_))
        ));
    }
}
