//! Local account provisioning (plan §8.4) and credential verification
//! (§8.1) for the endpoint agent.
//!
//! Provisioning reconciles the local account from the server's POSIX
//! mapping via established shadow tools (`groupadd` / `useradd`) invoked as
//! child processes with argument arrays — never shell concatenation
//! (§12.3). Idempotent: an existing account with matching uid/username is
//! accepted; a mismatch (uid or username shadowing an existing identity) is
//! an error, never silently "fixed" (§8.4: provisioning must reject names or
//! IDs that shadow existing local identities).
//!
//! Credential verification delegates to `unix_chkpwd` (the shadow suite's
//! helper, designed for exactly this) — established tooling, no new crypto.
//! The agent is root, so the helper can read the shadow hash for the
//! requested account. Rate limiting (§5.1) is enforced per local username
//! before the helper runs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("provisioning I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// The POSIX mapping carried in the check-in response (§8.4).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct PosixMapping {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    #[serde(default)]
    pub full_name: String,
}

/// The system passwd/group databases, read via getent (established tooling;
/// NSS-agnostic reading of what the local system currently has).
fn getent(database: &str, key: &str) -> Option<String> {
    let output = Command::new("getent")
        .arg(database)
        .arg(key)
        .output()
        .ok()?;
    if output.status.success() {
        String::from_utf8(output.stdout).ok()
    } else {
        None
    }
}

fn uid_of(username: &str) -> Option<u32> {
    getent("passwd", username).and_then(|line| {
        line.lines()
            .next()
            .and_then(|l| l.split(':').nth(2)?.parse::<u32>().ok())
    })
}

fn group_exists(gid: u32) -> bool {
    getent("group", &gid.to_string()).is_some()
}

fn user_exists(username: &str) -> bool {
    getent("passwd", username).is_some()
}

/// Ensure a user-private group named after the account exists (§8.4).
fn ensure_group(gid: u32, group_name: &str) -> Result<(), ProvisionError> {
    if group_exists(gid) {
        return Ok(());
    }
    let status = Command::new("groupadd")
        .arg("--gid")
        .arg(gid.to_string())
        .arg(group_name)
        .output()
        .map_err(ProvisionError::Io)?;
    if status.status.success() || group_exists(gid) {
        Ok(())
    } else {
        Err(ProvisionError::Message(format!(
            "groupadd --gid {gid} failed: {}",
            String::from_utf8_lossy(&status.stderr)
        )))
    }
}

/// Ensure the local account matches the server's POSIX mapping:
/// - missing → `useradd` with the mapped uid/gid/home/shell + `-m` (home);
/// - existing with the same username → uid must match (else collision error);
/// - the username/uid shadowing a DIFFERENT identity → error (§8.4).
pub fn ensure_local_account(mapping: &PosixMapping) -> Result<(), ProvisionError> {
    if let Some(existing_uid) = uid_of(&mapping.username) {
        if existing_uid == mapping.uid {
            return Ok(()); // already provisioned correctly
        }
        return Err(ProvisionError::Message(format!(
            "local user {} exists with uid {existing_uid}, server maps uid {} (§8.4 collision)",
            mapping.username, mapping.uid
        )));
    }

    // The uid must not shadow a different local account either.
    if let Some(shadowed) = getent("passwd", &mapping.uid.to_string()) {
        let shadowed_name = shadowed.lines().next().unwrap_or("").split(':').next().unwrap_or("");
        return Err(ProvisionError::Message(format!(
            "uid {} is taken by local user {shadowed_name} (§8.4 collision)",
            mapping.uid
        )));
    }

    ensure_group(mapping.gid, &mapping.username)?;

    let status = Command::new("useradd")
        .arg("--uid")
        .arg(mapping.uid.to_string())
        .arg("--gid")
        .arg(mapping.gid.to_string())
        .arg("--create-home")
        .arg("--home-dir")
        .arg(&mapping.home)
        .arg("--shell")
        .arg(&mapping.shell)
        .arg("--comment")
        .arg(if mapping.full_name.is_empty() {
            mapping.username.clone()
        } else {
            mapping.full_name.clone()
        })
        .arg(&mapping.username)
        .output()
        .map_err(ProvisionError::Io)?;

    if !status.status.success() || !user_exists(&mapping.username) {
        return Err(ProvisionError::Message(format!(
            "useradd {} failed: {}",
            mapping.username,
            String::from_utf8_lossy(&status.stderr)
        )));
    }
    Ok(())
}

/// Rate limiter for credential attempts (§5.1): per local username, a fixed
/// number of failures within a window triggers a cooldown. In-process state
/// (single daemon); persisted ban lists are later work.
#[derive(Default)]
pub struct RateLimiter {
    failures: HashMap<String, Vec<Instant>>,
    max_failures: usize,
    window: Duration,
    cooldown: Duration,
}

#[derive(Debug, PartialEq)]
pub enum RateDecision {
    Allowed,
    Limited { retry_after_secs: u64 },
}

impl RateLimiter {
    pub fn new(max_failures: usize, window: Duration, cooldown: Duration) -> Self {
        Self {
            failures: HashMap::new(),
            max_failures,
            window,
            cooldown,
        }
    }

    pub fn check(&mut self, key: &str) -> RateDecision {
        let now = Instant::now();
        let window = self.window;
        let attempts = self
            .failures
            .entry(key.to_string())
            .or_default();
        attempts.retain(|t| now.duration_since(*t) < window);
        if attempts.len() >= self.max_failures {
            let oldest = attempts.first().copied().unwrap_or(now);
            let remaining = self
                .cooldown
                .checked_sub(now.duration_since(oldest))
                .unwrap_or(Duration::ZERO);
            return RateDecision::Limited {
                retry_after_secs: remaining.as_secs() + 1,
            };
        }
        RateDecision::Allowed
    }

    pub fn record_failure(&mut self, key: &str) {
        self.failures
            .entry(key.to_string())
            .or_default()
            .push(Instant::now());
    }

    pub fn record_success(&mut self, key: &str) {
        self.failures.remove(key);
    }
}

/// libxcrypt's crypt(3) — the SAME implementation pam_unix calls internally
/// (yescrypt, sha512crypt, ...). The agent does not reimplement any hashing
/// primitive (§8.1). `unix_chkpwd` was evaluated first and rejected: it
/// deliberately refuses direct invocation by root (it is built only for the
/// setuid transition with a non-root real uid — a password-oracle
/// protection), which makes it unusable for the root agent.
mod libcrypt {
    use std::ffi::{c_char, CStr, CString};

    #[link(name = "crypt")]
    unsafe extern "C" {
        fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
    }

    static CRYPT_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// crypt(3) returns a static buffer; the mutex serializes access (the
    /// accept loop is single-threaded, the lock is defense in depth).
    pub fn verify(setting: &str, key: &str) -> Option<String> {
        let setting = CString::new(setting).ok()?;
        let key = CString::new(key).ok()?;
        let _guard = CRYPT_MUTEX.lock().ok()?;
        let result = unsafe { crypt(key.as_ptr(), setting.as_ptr()) };
        if result.is_null() {
            return None;
        }
        Some(unsafe { CStr::from_ptr(result) }.to_string_lossy().into_owned())
    }
}

/// Read the password hash field from /etc/shadow for a local account.
/// The agent is root (the privileged component, §11.1); an unknown account
/// returns None → the caller fails closed.
fn shadow_hash_for(username: &str) -> Option<String> {
    let shadow = std::fs::read_to_string("/etc/shadow").ok()?;
    for line in shadow.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(username) {
            return fields.next().map(|hash| hash.to_string()).filter(|h| !h.is_empty());
        }
    }
    None
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a local account password: parse the shadow hash, crypt(3) the
/// presented password with the stored setting, compare constant-time.
/// Locked accounts (`!`, `*` prefixes) never verify. No password material
/// is logged or stored by the agent (§5.1).
pub fn verify_local_password(username: &str, password: &str) -> bool {
    let Some(setting) = shadow_hash_for(username) else {
        return false; // unknown account → fail closed (no oracle)
    };
    // Locked / passwordless accounts never authenticate (§8.4 retirement
    // behavior and provisioning-before-login state).
    if setting.starts_with('!') || setting.starts_with('*') {
        return false;
    }
    let Some(computed) = libcrypt::verify(&setting, password) else {
        return false; // unsupported scheme or crypt failure → fail closed
    };
    constant_time_eq(computed.as_bytes(), setting.as_bytes())
}

/// Credential verification with rate limiting, wired into the PAM decision
/// path. Returns true when the password is accepted.
pub struct CredentialVerifier {
    limiter: std::sync::Mutex<RateLimiter>,
}

impl CredentialVerifier {
    pub fn new() -> Self {
        // §5.1: bounded attempts; 5 failures / 15 minutes → cooldown.
        Self {
            limiter: std::sync::Mutex::new(RateLimiter::new(
                5,
                Duration::from_secs(15 * 60),
                Duration::from_secs(15 * 60),
            )),
        }
    }

    pub fn verify(&self, local_username: &str, password: &str) -> bool {
        {
            let mut limiter = self.limiter.lock().expect("rate limiter mutex");
            if let RateDecision::Limited { retry_after_secs } = limiter.check(local_username) {
                let _ = retry_after_secs; // opaque denial: no timing detail to the client
                return false;
            }
            let ok = verify_local_password(local_username, password);
            if ok {
                limiter.record_success(local_username);
            } else {
                limiter.record_failure(local_username);
            }
            ok
        }
    }
}

impl Default for CredentialVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Check a provisioning mapping file for sanity before use (defense in
/// depth: paths must stay under /home, shells must be absolute).
pub fn validate_mapping(mapping: &PosixMapping) -> Result<(), ProvisionError> {
    if !mapping.home.starts_with("/home/") || mapping.home.contains("..") {
        return Err(ProvisionError::Message(format!(
            "home {:?} must be under /home",
            mapping.home
        )));
    }
    if !mapping.shell.starts_with('/') {
        return Err(ProvisionError::Message(format!(
            "shell {:?} must be an absolute path",
            mapping.shell
        )));
    }
    Ok(())
}

/// Read a POSIX mapping from a JSON file (test/tooling helper).
pub fn read_mapping(path: &Path) -> Result<PosixMapping, ProvisionError> {
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}
