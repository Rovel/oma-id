//! `pam_oma_id` — thin libpam front end for the OMA-ID agent.
//!
//! Per ADR-0004 this module contains no policy engine, credential database,
//! HTTP client or remotely supplied scripting: it reads the PAM service and
//! user from the handle, asks the local agent over the root-owned Unix
//! socket, and translates the fail-closed [`oma_id_pam_client::Outcome`] into
//! a PAM return code.
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

// PAM return codes (libpam/pam_modules.h).
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_SYSTEM_ERR: c_int = 1;
pub const PAM_BUF_ERR: c_int = 2;
pub const PAM_PERM_DENIED: c_int = 3;
pub const PAM_AUTH_ERR: c_int = 6;

// PAM item types (libpam/pam_items.h).
const PAM_SERVICE: c_int = 1;
const PAM_USER: c_int = 2;

/// Fixed agent socket. See the crate docs: no environment override.
pub const AGENT_SOCKET_PATH: &str = "/run/oma-id/agent.sock";

type PamHandle = *mut c_void;

#[derive(Clone, Copy, Debug)]
pub enum Stage {
    /// `pam_sm_auth`: credential stage.
    Auth,
    /// `pam_sm_acct_mgmt`: account management stage. Per the plan, account
    /// checks must also obtain an explicit agent authorization decision.
    Account,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_auth(
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
    // SAFETY: `handle` is the live PAM handle for this invocation.
    let items = match unsafe { read_items(handle) } {
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
    outcome_to_pam_code(stage, client.authorize(consumer, operation, &user))
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
/// `pam_get_item`.
unsafe fn read_items(handle: PamHandle) -> Result<PamItems, c_int> {
    let lib = dlopen_libpam().ok_or(PAM_SYSTEM_ERR)?;
    type PamGetItem = unsafe extern "C" fn(*mut c_void, c_int, *mut *const c_void) -> c_int;
    // SAFETY: `lib` is a live dlopen handle; the symbol name is NUL-terminated.
    let sym = unsafe { libc::dlsym(lib, b"pam_get_item\0".as_ptr().cast::<c_char>()) };
    if sym.is_null() {
        // SAFETY: `lib` is a live handle from dlopen.
        unsafe { libc::dlclose(lib) };
        return Err(PAM_SYSTEM_ERR);
    }
    // SAFETY: `pam_get_item` has a stable C ABI; transmuting a non-null
    // dlsym result into that function-pointer type preserves provenance.
    let get_item = unsafe { std::mem::transmute::<*mut c_void, PamGetItem>(sym) };
    // SAFETY: `get_item` is the resolved libpam entry point; the handle and
    // item pointers are valid for this module invocation.
    let service = unsafe { item_string(get_item, handle, PAM_SERVICE) }?;
    let user = unsafe { item_string(get_item, handle, PAM_USER) }?;
    // SAFETY: `lib` is a live handle from dlopen.
    unsafe { libc::dlclose(lib) };
    Ok(PamItems { service, user })
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
