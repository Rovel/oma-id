//! Fake root-owned Unix socket service for OMA-ID agent P0 experiments.
//!
//! This crate proves the privileged side of the local authorization socket
//! before any PAM module exists: peer identity, framing failure, timeout,
//! daemon-down and lease-decision mapping. It is a protocol stand-in, not the
//! production daemon: no configuration loading, persistence, revocation
//! polling or service supervision. The production agent will own its lease
//! store; here the caller supplies an already-verified lease.
//!
//! Denial mapping is deliberately opaque. Peer identity failures, unknown
//! local accounts and every lease-decision denial map to
//! `Deny(NotAuthorized)`. Only protocol-level validation failures map to
//! `Deny(InvalidRequest)`, and only when the body parsed well enough to
//! recover its correlation id. This keeps clients from learning which local
//! accounts exist or which lease field failed.

#![cfg(target_os = "linux")]

use oma_id_agent_core::{self as core};
use oma_id_agent_ipc::{
    authorize_peer, peer_credentials, read_message, write_message, AuthorizationRequest,
    AuthorizationResponse, Consumer as IpcConsumer, Decision, DenialCode, Operation as IpcOperation,
    PeerCredentials, PROTOCOL_VERSION,
};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Upper bound for a single request/response exchange. A PAM consumer that
/// cannot answer within this window gets a fail-closed timeout, not a hang.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ServiceConfig<'a> {
    pub socket_path: &'a Path,
    /// Already-verified lease; signature parsing stays outside this crate.
    pub lease: core::VerifiedLease<'a>,
    pub trusted_time_floor: u64,
    pub minimum_revocation_epoch: u64,
}

/// Bind the service socket and restrict it to the owning user. Production
/// runs the agent as root, so a `0o600` socket keeps every non-root consumer
/// out at the filesystem layer before peer policy even applies.
pub fn bind(socket_path: &Path) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(
        socket_path,
        std::fs::Permissions::from_mode(0o600),
    )?;
    Ok(listener)
}

/// Accept loop. Returns when the listener itself fails; per-connection
/// failures never take the service down.
pub fn serve(config: &ServiceConfig) -> io::Result<()> {
    let listener = bind(config.socket_path)?;
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            handle_connection(&mut stream, config);
        }
    }
    Ok(())
}

/// Handle one connection to completion. Public so tests can drive a single
/// exchange without the accept loop.
pub fn handle_connection(stream: &mut UnixStream, config: &ServiceConfig) {
    // A peer that cannot be identified by the kernel is denied before any
    // bytes are read.
    let peer = match peer_credentials(stream) {
        Ok(peer) => peer,
        Err(_) => return,
    };
    if stream
        .set_read_timeout(Some(CONNECTION_TIMEOUT))
        .or_else(|_| stream.set_write_timeout(Some(CONNECTION_TIMEOUT)))
        .is_err()
    {
        return;
    }
    let request = match read_message::<AuthorizationRequest>(stream) {
        Ok(request) => request,
        // Framing failures (size, EOF, malformed JSON) leave no correlation
        // id to answer with; closing is the only fail-closed reply.
        Err(_) => return,
    };
    let response = AuthorizationResponse {
        version: PROTOCOL_VERSION,
        request_id: request.request_id,
        decision: decide(&request, &peer, config),
    };
    let _ = write_message(stream, &response);
}

fn decide(
    request: &AuthorizationRequest,
    peer: &PeerCredentials,
    config: &ServiceConfig,
) -> Decision {
    if request.validate().is_err() {
        return Decision::Deny(DenialCode::InvalidRequest);
    }
    // Trusted local account lookup; the uid never comes from the request.
    // An unknown name is denied like any other authorization failure so the
    // socket does not become an account-existence oracle.
    let local_user_uid = match local_user_uid(&request.local_username) {
        Some(uid) => uid,
        None => return Decision::Deny(DenialCode::NotAuthorized),
    };
    if authorize_peer(
        *peer,
        local_user_uid,
        request.consumer,
        request.operation,
    )
    .is_err()
    {
        return Decision::Deny(DenialCode::NotAuthorized);
    }
    match authorize_lease(request, config) {
        Ok(()) => Decision::Allow,
        Err(_) => Decision::Deny(DenialCode::NotAuthorized),
    }
}

fn authorize_lease(
    request: &AuthorizationRequest,
    config: &ServiceConfig,
) -> Result<(), core::Denial> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    // The fake service trusts its own bound lease for subject/device; the
    // production agent resolves person and device from local account state
    // before calling the core.
    core::authorize(
        &config.lease,
        &core::Request {
            subject_id: config.lease.subject_id,
            device_id: config.lease.device_id,
            consumer: to_core_consumer(request.consumer),
            operation: to_core_operation(request.operation),
            now,
            trusted_time_floor: config.trusted_time_floor,
            minimum_revocation_epoch: config.minimum_revocation_epoch,
        },
    )
}

fn to_core_consumer(consumer: IpcConsumer) -> core::Consumer {
    match consumer {
        IpcConsumer::Sddm => core::Consumer::Sddm,
        IpcConsumer::Quickshell => core::Consumer::Quickshell,
        IpcConsumer::Tty => core::Consumer::Tty,
        IpcConsumer::Sudo => core::Consumer::Sudo,
        IpcConsumer::Polkit => core::Consumer::Polkit,
        IpcConsumer::Ssh => core::Consumer::Ssh,
    }
}

fn to_core_operation(operation: IpcOperation) -> core::Operation {
    match operation {
        IpcOperation::Login => core::Operation::Login,
        IpcOperation::Unlock => core::Operation::Unlock,
        IpcOperation::Elevate => core::Operation::Elevate,
        IpcOperation::RemoteLogin => core::Operation::RemoteLogin,
    }
}

/// Trusted local account lookup by name. Returns `None` for unknown names or
/// library failures; both are indistinguishable on purpose.
fn local_user_uid(name: &str) -> Option<u32> {
    let mut nul = name.as_bytes().to_vec();
    nul.push(0);
    let mut buffer = vec![0_u8; 4096];
    let mut entry = MaybeUninit::<libc::passwd>::uninit();
    loop {
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `nul` is NUL-terminated and outlives the call; `entry`
        // provides writable passwd storage; `buffer` is the scratch area of
        // the advertised size; `found` receives either null or a pointer into
        // that storage, which we only dereference after success.
        let status = unsafe {
            libc::getpwnam_r(
                nul.as_ptr().cast::<libc::c_char>(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast::<libc::c_char>(),
                buffer.len(),
                &mut found,
            )
        };
        if status == libc::ERANGE {
            let next = buffer.len().saturating_mul(2).max(8192);
            buffer.resize(next, 0);
            continue;
        }
        if status != 0 || found.is_null() {
            return None;
        }
        // SAFETY: getpwnam_r succeeded and `found` aliases our entry.
        let entry = unsafe { &*found };
        return Some(entry.pw_uid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_known_and_unknown_local_accounts() {
        assert_eq!(local_user_uid("root"), Some(0));
        assert_eq!(local_user_uid("definitely-not-an-oma-user"), None);
    }

    #[test]
    fn maps_every_ipc_consumer_and_operation() {
        for consumer in [
            IpcConsumer::Sddm,
            IpcConsumer::Quickshell,
            IpcConsumer::Tty,
            IpcConsumer::Sudo,
            IpcConsumer::Polkit,
            IpcConsumer::Ssh,
        ] {
            assert!(matches!(
                to_core_consumer(consumer),
                core::Consumer::Sddm
                    | core::Consumer::Quickshell
                    | core::Consumer::Tty
                    | core::Consumer::Sudo
                    | core::Consumer::Polkit
                    | core::Consumer::Ssh
            ));
        }
        for operation in [
            IpcOperation::Login,
            IpcOperation::Unlock,
            IpcOperation::Elevate,
            IpcOperation::RemoteLogin,
        ] {
            assert!(matches!(
                to_core_operation(operation),
                core::Operation::Login
                    | core::Operation::Unlock
                    | core::Operation::Elevate
                    | core::Operation::RemoteLogin
            ));
        }
    }
}
