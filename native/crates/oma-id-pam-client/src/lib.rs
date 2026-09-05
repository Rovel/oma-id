//! Thin consumer-side client for the OMA-ID agent authorization socket.
//!
//! This is the Rust core that `pam_oma_id` wraps. Per ADR-0004 and the plan,
//! the PAM client is limited to forwarding authorization requests over the
//! authenticated local IPC; credential verification, rate limiting and lease
//! decisions stay in the agent.
//!
//! Fail-closed contract: only [`Outcome::Authorized`] may be treated as a
//! pass by the PAM layer. Every other outcome — explicit denial, daemon down,
//! timeout, protocol violation, or an unusable PAM context — must block the
//! operation. This is what keeps a valid local credential from overriding an
//! expired, revoked, wrong-device or wrong-person lease: the client never
//! falls back to anything else.
//!
//! `local_username` must come from the PAM context (the account the consumer
//! is authenticating), never from user input on the wire. The actual libpam
//! glue and credential-exchange message type are later slices.

#![cfg(target_os = "linux")]

use oma_id_agent_ipc::{exchange, ProtocolError, PROTOCOL_VERSION};

pub use oma_id_agent_ipc::{Consumer, Operation};
use std::path::PathBuf;
use std::time::Duration;

/// Default upper bound for one authorization round trip. A desktop unlock or
/// login should fail closed well before the user gives up on the box.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

const REQUEST_ID_BYTES: usize = 16;
const RANDOM_DEVICE: &str = "/dev/urandom";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnavailableReason {
    /// The socket could not be reached (missing daemon, permission denied).
    ConnectFailed,
    /// The agent accepted the connection but did not answer in time.
    TimedOut,
    /// A decision was received but violated the protocol (framing, version,
    /// correlation id), or the request itself could not be formed.
    ProtocolViolation,
    /// Local failure before talking to the agent (e.g. no entropy source).
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The agent explicitly authorized this consumer/operation for this
    /// local account. The only pass condition.
    Authorized,
    /// The agent explicitly denied the request. Denial codes are opaque by
    /// design; the client must not branch on them.
    Denied,
    /// No decision could be obtained. Fail closed, and alert-worthy.
    Unavailable(UnavailableReason),
}

pub struct Client {
    socket_path: PathBuf,
    timeout: Duration,
}

impl Client {
    pub fn new(socket_path: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout,
        }
    }

    /// Ask the agent to authorize `operation` for `local_username`, on behalf
    /// of the PAM consumer this module instance represents.
    pub fn authorize(
        &self,
        consumer: Consumer,
        operation: Operation,
        local_username: &str,
    ) -> Outcome {
        let request_id = match random_request_id() {
            Some(id) => id,
            None => return Outcome::Unavailable(UnavailableReason::Internal),
        };
        let request = oma_id_agent_ipc::AuthorizationRequest {
            version: PROTOCOL_VERSION,
            request_id,
            local_username: local_username.to_owned(),
            consumer,
            operation,
        };
        match exchange(&self.socket_path, &request, self.timeout) {
            Ok(response) => match response.decision {
                oma_id_agent_ipc::Decision::Allow => Outcome::Authorized,
                oma_id_agent_ipc::Decision::Deny(_) => Outcome::Denied,
            },
            Err(error) => Outcome::Unavailable(map_error(&error)),
        }
    }
}

fn map_error(error: &ProtocolError) -> UnavailableReason {
    match error {
        ProtocolError::Io(io_error) => match io_error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                UnavailableReason::TimedOut
            }
            // Missing socket file, connection refused, reset: no agent.
            std::io::ErrorKind::NotFound
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::PermissionDenied => UnavailableReason::ConnectFailed,
            // Anything else (including a half-dead connection) still means we
            // got no decision; classify it as a broken exchange.
            _ => UnavailableReason::ProtocolViolation,
        },
        ProtocolError::Json(_)
        | ProtocolError::EmptyMessage
        | ProtocolError::MessageTooLarge(_)
        | ProtocolError::UnsupportedVersion(_)
        | ProtocolError::RequestIdMismatch
        | ProtocolError::InvalidLocalUsername => UnavailableReason::ProtocolViolation,
    }
}

/// 16 random bytes from the kernel; no third-party RNG dependency.
fn random_request_id() -> Option<[u8; REQUEST_ID_BYTES]> {
    let mut file = std::fs::File::open(RANDOM_DEVICE).ok()?;
    let mut id = [0_u8; REQUEST_ID_BYTES];
    use std::io::Read;
    file.read_exact(&mut id).ok()?;
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_are_random_and_full_width() {
        let a = random_request_id().expect("entropy");
        let b = random_request_id().expect("entropy");
        assert_ne!(a, b);
        assert_eq!(a.len(), REQUEST_ID_BYTES);
    }

    #[test]
    fn maps_every_protocol_failure_to_a_fail_closed_reason() {
        for outcome in [
            Outcome::Denied,
            Outcome::Unavailable(UnavailableReason::ConnectFailed),
            Outcome::Unavailable(UnavailableReason::TimedOut),
            Outcome::Unavailable(UnavailableReason::ProtocolViolation),
            Outcome::Unavailable(UnavailableReason::Internal),
        ] {
            assert_ne!(outcome, Outcome::Authorized);
        }
    }

    #[test]
    fn socket_path_is_retained() {
        let client = Client::new("/run/oma-id/agent.sock", DEFAULT_TIMEOUT);
        assert_eq!(client.socket_path, PathBuf::from("/run/oma-id/agent.sock"));
        assert_eq!(client.timeout, DEFAULT_TIMEOUT);
    }
}
