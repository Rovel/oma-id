//! Bounded local IPC types and framing for the OMA-ID PAM client and agent.
//!
//! This protocol never carries passwords or enrollment tokens. Credential
//! exchange gets its own reviewed message type after the authorization path is
//! proven. The only supported target is Linux, matching Omarchy.

#![cfg(target_os = "linux")]

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024;
pub const MAX_LOCAL_USERNAME_BYTES: usize = 32;

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationResponse {
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

pub fn exchange(
    socket_path: &Path,
    request: &AuthorizationRequest,
    timeout: Duration,
) -> Result<AuthorizationResponse, ProtocolError> {
    request.validate()?;
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write_message(&mut stream, request)?;
    let response: AuthorizationResponse = read_message(&mut stream)?;
    if response.version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(response.version));
    }
    if response.request_id != request.request_id {
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
            let received: AuthorizationRequest = read_message(&mut server).expect("request");
            received.validate().expect("valid request");
            write_message(
                &mut server,
                &AuthorizationResponse {
                    version: PROTOCOL_VERSION,
                    request_id: received.request_id,
                    decision: Decision::Allow,
                },
            )
            .expect("response");
        });
        write_message(&mut client, &request()).expect("write request");
        let response: AuthorizationResponse = read_message(&mut client).expect("read response");
        assert_eq!(response.decision, Decision::Allow);
        assert_eq!(response.request_id, request().request_id);
        worker.join().expect("server worker");
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
        let body = br#"{"version":1,"request_id":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"local_username":"user","consumer":"tty","operation":"login","extra":true}"#;
        let mut frame = Vec::from((body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body);
        assert!(matches!(
            read_message::<AuthorizationRequest>(&mut frame.as_slice()),
            Err(ProtocolError::Json(_))
        ));

        let mut invalid = request();
        invalid.version = 2;
        assert!(matches!(
            invalid.validate(),
            Err(ProtocolError::UnsupportedVersion(2))
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
        let error = read_message::<AuthorizationResponse>(&mut client).expect_err("must timeout");
        assert!(matches!(
            error,
            ProtocolError::Io(ref io_error)
                if matches!(io_error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
        ));

        let path =
            std::env::temp_dir().join(format!("oma-id-agent-{}-missing.sock", std::process::id()));
        assert!(matches!(
            exchange(&path, &request(), Duration::from_millis(20)),
            Err(ProtocolError::Io(_))
        ));
    }
}
