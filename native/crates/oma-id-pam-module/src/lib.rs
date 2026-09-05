//! `pam_oma_id` — thin libpam front end for the OMA-ID agent.
//!
//! Per ADR-0004 this module contains no policy engine, credential database,
//! HTTP client or remotely supplied scripting: it reads the PAM service and
//! user from the handle, asks the conversation for the password (echo off),
//! forwards it to the local agent over the root-owned Unix socket, and
//! translates the fail-closed [`oma_id_pam_client::Outcome`] into a PAM
//! return code.
//!
//! Security decisions encoded here:
//!
//! - The agent socket path is a compile-time constant. There is
//!   deliberately **no** environment override: the PAM environment is
//!   caller-influenced, and an overridable path would let a local attacker
//!   point the module at their own always-allowing agent.
//! - Only `Authorized` maps to `PAM_SUCCESS`. Explicit denial maps to a
//!   stage-specific error; any unavailable outcome maps to
//!   `PAM_SYSTEM_ERR` so "agent dead" is auditable and distinct from "agent
//!   said no".
//! - The auth stage requires **both** decisions: the credential must verify
//!   AND the lease must authorize ([`authenticate_outcomes`]). A verified
//!   credential never extends or overrides a lease, and a lease denial is
//!   never rescued by one (plan §9.1). The password itself is forwarded to
//!   the agent and never stored, logged, or echoed.
//! - An unknown PAM service fails closed. The module must only be listed in
//!   OMA-managed PAM stacks; transparency for foreign services is a
//!   lockout-bypass vector, not a convenience.
//!
//! `libpam` is resolved at runtime with `dlopen`, so the crate builds on any
//! Linux host (WSL included) and links nothing beyond libc.

#![cfg(target_os = "linux")]

use oma_id_pam_client::{Client, Outcome, DEFAULT_TIMEOUT};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

// PAM return codes (Linux-PAM <security/_pam_types.h>).
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_SYSTEM_ERR: c_int = 4;
pub const PAM_BUF_ERR: c_int = 5;
pub const PAM_PERM_DENIED: c_int = 6;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_CONV_ERR: c_int = 16;

// PAM item types (libpam/pam_items.h).
const PAM_SERVICE: c_int = 1;
const PAM_USER: c_int = 2;

// `pam_prompt` echo mode (libpam/pam_misc/pam_prompt.h).
const PAM_PROMPT_ECHO_OFF: c_int = 1;

/// Fixed agent socket. See the crate docs: no environment override.
pub const AGENT_SOCKET_PATH: &str = "/run/oma-id/agent.sock";

type PamHandle = *mut c_void;

#[derive(Clone, Copy, Debug)]
pub enum Stage {
    /// `pam_sm_authenticate`: credential stage.
    Auth,
    /// `pam_sm_acct_mgmt`: account management stage. Per the plan, account
    /// checks must also obtain an explicit agent authorization decision.
    Account,
}

// Linux-PAM resolves the auth-stage entry point as `pam_sm_authenticate`
// (pam_handlers.c), not `pam_sm_auth` — exporting the wrong name makes
// libpam return PAM_MODULE_UNKNOWN without ever calling us.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    handle: PamHandle,
    fmt: c_int,
    argv: *const *const c_char,
    retdata: *mut c_void,
) -> c_int {
    unsafe { authorize_stage(handle, Stage::Auth, fmt, argv, retdata) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    handle: PamHandle,
    fmt: c_int,
    argv: *const *const c_char,
    retdata: *mut c_void,
) -> c_int {
    unsafe { authorize_stage(handle, Stage::Account, fmt, argv, retdata) }
}

unsafe fn authorize_stage(
    handle: PamHandle,
    stage: Stage,
    _fmt: c_int,
    _argv: *const *const c_char,
    _retdata: *mut c_void,
) -> c_int {
    // SAFETY: RTLD_NOW dlopen fails fast on a broken libpam; one handle is
    // shared by both resolved symbols and closed exactly once below.
    let lib = match dlopen_libpam() {
        Some(lib) => lib,
        None => return PAM_SYSTEM_ERR,
    };
    let result = unsafe { run_stage(handle, stage, lib) };
    // SAFETY: `lib` is the live handle from above and no resolved symbols
    // are in use once the stage has finished.
    let _ = unsafe { libc::dlclose(lib) };
    result
}

unsafe fn run_stage(handle: PamHandle, stage: Stage, lib: *mut c_void) -> c_int {
    // SAFETY: `handle` is the live PAM handle for this invocation.
    let items = match unsafe { read_items(lib, handle) } {
        Ok(items) => items,
        Err(code) => return code,
    };
    let (service, user) = (items.service, items.user);
    let (consumer, operation) = match map_service(&service) {
        Some(pair) => pair,
        None => return PAM_SYSTEM_ERR,
    };
    // The username comes from the PAM context, never from the wire.
    let client = Client::new(AGENT_SOCKET_PATH, DEFAULT_TIMEOUT);
    match stage {
        Stage::Account => {
            // Account checks require an explicit agent decision but never
            // prompt: the password belongs to the auth stage.
            outcome_to_pam_code(
                Stage::Account,
                client.authorize(consumer, operation, &user),
            )
        }
        Stage::Auth => {
            let password = match unsafe { prompt_password(lib, handle) } {
                Ok(password) => password,
                Err(code) => return code,
            };
            // Plan §9.1: both decisions are required. The credential answer
            // is reported first and never masked by the other.
            let credential = client.exchange_credential(consumer, operation, &user, &password);
            let authorization = client.authorize(consumer, operation, &user);
            authenticate_outcomes(credential, authorization)
        }
    }
}

/// Auth-stage decision rule: the forwarded credential must verify AND the
/// lease must authorize. Failures are reported in that order, so a dead
/// agent at the credential step is never masked by an authorization answer,
/// and a verified credential never rescues a lease denial.
pub fn authenticate_outcomes(credential: Outcome, authorization: Outcome) -> c_int {
    if !matches!(credential, Outcome::Authorized) {
        return outcome_to_pam_code(Stage::Auth, credential);
    }
    outcome_to_pam_code(Stage::Auth, authorization)
}

/// Map a PAM service name to the consumer/operation pair it represents.
/// Unknown services return `None` and fail closed at the call site.
pub fn map_service(service: &str) -> Option<(oma_id_pam_client::Consumer, oma_id_pam_client::Operation)> {
    use oma_id_pam_client::{Consumer, Operation};
    match service {
        "sddm" => Some((Consumer::Sddm, Operation::Login)),
        // Omarchy Quickshell lockers: password and fingerprint PAM contexts.
        "omarchy-lock-password" | "omarchy-lock-fingerprint" => {
            Some((Consumer::Quickshell, Operation::Unlock))
        }
        _ => None,
    }
}

/// Translate the client outcome into a PAM return code for the stage.
pub fn outcome_to_pam_code(stage: Stage, outcome: Outcome) -> c_int {
    match outcome {
        Outcome::Authorized => PAM_SUCCESS,
        Outcome::Denied => match stage {
            Stage::Auth => PAM_AUTH_ERR,
            Stage::Account => PAM_PERM_DENIED,
        },
        Outcome::Unavailable(_) => PAM_SYSTEM_ERR,
    }
}

struct PamItems {
    service: String,
    user: String,
}

/// Read `PAM_SERVICE` and `PAM_USER` from the handle via a runtime-resolved
/// `pam_get_item`. The caller owns `lib` (and its close).
unsafe fn read_items(lib: *mut c_void, handle: PamHandle) -> Result<PamItems, c_int> {
    type PamGetItem = unsafe extern "C" fn(*mut c_void, c_int, *mut *const c_void) -> c_int;
    // SAFETY: `lib` is a live dlopen handle; the symbol name is NUL-terminated.
    let sym = unsafe { libc::dlsym(lib, b"pam_get_item\0".as_ptr().cast::<c_char>()) };
    if sym.is_null() {
        return Err(PAM_SYSTEM_ERR);
    }
    // SAFETY: `pam_get_item` has a stable C ABI; transmuting a non-null
    // dlsym result into that function-pointer type preserves provenance.
    let get_item = unsafe { std::mem::transmute::<*mut c_void, PamGetItem>(sym) };
    // SAFETY: `get_item` is the resolved libpam entry point; the handle and
    // item pointers are valid for this module invocation.
    let service = unsafe { item_string(get_item, handle, PAM_SERVICE) }?;
    let user = unsafe { item_string(get_item, handle, PAM_USER) }?;
    Ok(PamItems { service, user })
}

/// Ask the conversation for the user's password with echo off, via a
/// runtime-resolved `pam_prompt`. The response string is copied out and
/// freed — libpam leaves ownership with us. Any non-success from libpam is
/// returned as-is so a user abort stays an abort.
unsafe fn prompt_password(lib: *mut c_void, handle: PamHandle) -> Result<String, c_int> {
    type PamPrompt = unsafe extern "C" fn(*mut c_void, c_int, *const c_char, *mut c_void) -> c_int;
    // SAFETY: `lib` is a live dlopen handle; the symbol name is NUL-terminated.
    let sym = unsafe { libc::dlsym(lib, b"pam_prompt\0".as_ptr().cast::<c_char>()) };
    if sym.is_null() {
        return Err(PAM_SYSTEM_ERR);
    }
    // SAFETY: `pam_prompt` has a stable C ABI; transmuting a non-null dlsym
    // result into that function-pointer type preserves provenance.
    let prompt = unsafe { std::mem::transmute::<*mut c_void, PamPrompt>(sym) };
    let mut response: *mut c_char = ptr::null_mut();
    // SAFETY: `handle` is the live PAM handle; `&mut response` is passed as
    // the `char **` auxiliary argument that `pam_prompt` fills in.
    let rc = unsafe {
        prompt(
            handle,
            PAM_PROMPT_ECHO_OFF,
            b"Password:\0".as_ptr().cast::<c_char>(),
            &mut response as *mut *mut c_char as *mut c_void,
        )
    };
    if rc != PAM_SUCCESS {
        return Err(rc);
    }
    if response.is_null() {
        return Err(PAM_CONV_ERR);
    }
    // SAFETY: libpam guarantees a NUL-terminated response for prompt items.
    let bytes = unsafe { CStr::from_ptr(response) }.to_bytes().to_vec();
    // SAFETY: `response` is heap-allocated by the conversation and owned by
    // us from this point on.
    unsafe { libc::free(response as *mut c_void) };
    String::from_utf8(bytes).map_err(|_| PAM_BUF_ERR)
}

unsafe fn item_string(
    get_item: unsafe extern "C" fn(*mut c_void, c_int, *mut *const c_void) -> c_int,
    handle: PamHandle,
    item_type: c_int,
) -> Result<String, c_int> {
    let mut item: *const c_void = ptr::null_mut();
    // SAFETY: `handle` is the live PAM handle for this module invocation and
    // `item` receives a pointer owned by libpam for the call's duration.
    let rc = unsafe { get_item(handle, item_type, &mut item) };
    if rc != PAM_SUCCESS || item.is_null() {
        return Err(PAM_BUF_ERR);
    }
    // SAFETY: libpam guarantees a NUL-terminated string for string items.
    let bytes = unsafe { CStr::from_ptr(item as *const c_char) }.to_bytes();
    String::from_utf8(bytes.to_vec()).map_err(|_| PAM_BUF_ERR)
}

fn dlopen_libpam() -> Option<*mut c_void> {
    // SAFETY: NUL-terminated name; RTLD_NOW resolves immediately so a broken
    // library fails here, not mid-authentication.
    let handle =
        unsafe { libc::dlopen(b"libpam.so.0\0".as_ptr().cast::<c_char>(), libc::RTLD_NOW) };
    if handle.is_null() {
        None
    } else {
        Some(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oma_id_pam_client::{Consumer, Operation, UnavailableReason};

    #[test]
    fn maps_known_oma_services_only() {
        assert_eq!(
            map_service("sddm"),
            Some((Consumer::Sddm, Operation::Login))
        );
        for service in ["omarchy-lock-password", "omarchy-lock-fingerprint"] {
            assert_eq!(
                map_service(service),
                Some((Consumer::Quickshell, Operation::Unlock))
            );
        }
        // Unknown or foreign services fail closed.
        for service in ["", "login", "sshd", "su", "sudo", "systemd-user"] {
            assert_eq!(map_service(service), None);
        }
    }

    #[test]
    fn only_explicit_allow_succeeds() {
        let allow = Outcome::Authorized;
        for stage in [Stage::Auth, Stage::Account] {
            assert_eq!(outcome_to_pam_code(stage, allow), PAM_SUCCESS);
        }
        let failures: [Outcome; 5] = [
            Outcome::Denied,
            Outcome::Unavailable(UnavailableReason::ConnectFailed),
            Outcome::Unavailable(UnavailableReason::TimedOut),
            Outcome::Unavailable(UnavailableReason::ProtocolViolation),
            Outcome::Unavailable(UnavailableReason::Internal),
        ];
        for stage in [Stage::Auth, Stage::Account] {
            for outcome in failures {
                assert_ne!(outcome_to_pam_code(stage, outcome), PAM_SUCCESS);
            }
        }
    }

    #[test]
    fn auth_stage_requires_both_decisions_in_order() {
        // Both pass.
        assert_eq!(
            authenticate_outcomes(Outcome::Authorized, Outcome::Authorized),
            PAM_SUCCESS
        );
        // A credential failure is reported first...
        assert_eq!(
            authenticate_outcomes(Outcome::Denied, Outcome::Authorized),
            PAM_AUTH_ERR
        );
        assert_eq!(
            authenticate_outcomes(
                Outcome::Unavailable(UnavailableReason::ConnectFailed),
                Outcome::Authorized
            ),
            PAM_SYSTEM_ERR
        );
        // ...and a verified credential never rescues a lease denial.
        assert_eq!(
            authenticate_outcomes(Outcome::Authorized, Outcome::Denied),
            PAM_AUTH_ERR
        );
        assert_eq!(
            authenticate_outcomes(
                Outcome::Authorized,
                Outcome::Unavailable(UnavailableReason::TimedOut)
            ),
            PAM_SYSTEM_ERR
        );
    }

    #[test]
    fn denial_and_unavailable_are_distinct() {
        assert_eq!(outcome_to_pam_code(Stage::Auth, Outcome::Denied), PAM_AUTH_ERR);
        assert_eq!(
            outcome_to_pam_code(Stage::Account, Outcome::Denied),
            PAM_PERM_DENIED
        );
        for reason in [
            UnavailableReason::ConnectFailed,
            UnavailableReason::TimedOut,
            UnavailableReason::ProtocolViolation,
            UnavailableReason::Internal,
        ] {
            assert_eq!(
                outcome_to_pam_code(Stage::Auth, Outcome::Unavailable(reason)),
                PAM_SYSTEM_ERR
            );
        }
    }

    #[test]
    fn agent_socket_path_is_fixed_and_absolute() {
        assert_eq!(AGENT_SOCKET_PATH, "/run/oma-id/agent.sock");
        assert!(std::path::Path::new(AGENT_SOCKET_PATH).is_absolute());
    }
}
