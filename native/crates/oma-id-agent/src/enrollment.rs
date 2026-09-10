//! The P3-a enrollment transaction, agent side (plan §7.2, §7.3).
//!
//! On first contact a device with no accepted enrollment:
//! 1. collects its hardware identity from DMI (manufacturer/model/serial)
//!    and `/etc/machine-id`,
//! 2. POSTs an unauthenticated enrollment request (its key IS the identity
//!    claim; a pending request grants no organizational access, §7.3),
//! 3. polls a DEVICE-SIGNED status endpoint until an administrator accepts
//!    the request in the trusted browser. The signed poll is the §7.2
//!    step-4 key-possession proof the admin sees before accepting.
//!
//! Fail-closed boundaries preserved: an unreachable server still exits
//! non-zero; a `rejected` request is terminal for that key (§7.3) and the
//! agent exits; nothing is stored unless the server accepted the request.

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{persist_atomically, DeviceIdentity};

/// The hardware identity a device reports when asking to be enrolled
/// (§7.2 step 1: "minimally necessary device details").
#[derive(Clone, Debug, Default, Serialize)]
pub struct HardwareIdentity {
    pub device_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub machine_id: Option<String>,
}

/// The enrollment record persisted (0600) in the agent state directory once
/// the server accepted the request; the device_id there is the server-bound
/// identity used for every check-in afterwards.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    pub request_id: u64,
    pub device_id: String,
    pub accepted_at: u64,
}

#[derive(Debug, Deserialize)]
struct PostResponse {
    id: u64,
}

#[derive(Debug, Deserialize)]
struct StatusResponse {
    state: String,
    #[serde(default)]
    device: Option<AcceptedDevice>,
}

#[derive(Debug, Deserialize)]
struct AcceptedDevice {
    device_id: String,
}

fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Collect the hardware identity from DMI (§7.2 step 1). Every field is
/// individually optional: containers and VMs may expose none or only part,
/// and `product_serial` is root-restricted on some systems.
pub fn read_hardware_identity() -> HardwareIdentity {
    let dmi = Path::new("/sys/class/dmi/id");
    let vendor = read_trimmed(&dmi.join("sys_vendor"));
    let model = read_trimmed(&dmi.join("product_name"));
    let serial = read_trimmed(&dmi.join("product_serial"));
    let machine_id = read_trimmed(Path::new("/etc/machine-id"));

    let device_name = match (&vendor, &model) {
        (Some(v), Some(m)) => Some(format!("{v} {m}")),
        (Some(v), None) => Some(v.clone()),
        (None, Some(m)) => Some(m.clone()),
        (None, None) => machine_id.as_ref().map(|id| format!("Device (machine-id {id})",)),
    };

    HardwareIdentity {
        device_name,
        manufacturer: vendor,
        model,
        serial_number: serial.filter(|s| s.len() <= 200),
        machine_id,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("http: {0}")]
    Http(String),
    #[error("server rejected the enrollment call ({status}): {body}")]
    Rejected { status: u16, body: String },
    #[error("enrollment request {0} was rejected by an administrator")]
    RejectedByAdmin(u64),
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl From<crate::AgentError> for EnrollError {
    fn from(error: crate::AgentError) -> Self {
        EnrollError::Message(error.to_string())
    }
}

impl From<ureq::Error> for EnrollError {
    fn from(error: ureq::Error) -> Self {
        match error {
            ureq::Error::Status(status, response) => {
                let body = response.into_string().unwrap_or_default();
                EnrollError::Rejected { status, body }
            }
            other => EnrollError::Http(ureq::Error::to_string(&other)),
        }
    }
}

/// POST the enrollment request (idempotent per device key — a re-post
/// returns the same pending request, §7.2 "retries must not create
/// duplicates").
fn post_request(
    server_url: &str,
    identity: &DeviceIdentity,
    hardware: &HardwareIdentity,
    proposed_device_id: &str,
) -> Result<u64, EnrollError> {
    let url = format!(
        "{}/api/v1/enrollment-requests",
        server_url.trim_end_matches('/')
    );
    let response = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(ureq::json!({
            "requested_device_id": proposed_device_id,
            "public_key_hex": identity.public_key_hex,
            "device_name": hardware.device_name,
            "manufacturer": hardware.manufacturer,
            "model": hardware.model,
            "serial_number": hardware.serial_number,
            "machine_id": hardware.machine_id,
        }))?;
    let body = response.into_string().map_err(|e| EnrollError::Http(e.to_string()))?;
    let parsed: PostResponse = serde_json::from_str(&body)?;
    Ok(parsed.id)
}

/// One device-signed status poll (§7.2 step 4, minimal form): proves private
/// key possession server-side, which is what the admin reviews.
fn poll_status(
    server_url: &str,
    request_id: u64,
    identity: &DeviceIdentity,
) -> Result<StatusResponse, EnrollError> {
    let timestamp = now_secs();
    let message = format!("enrollment-status|{request_id}|{timestamp}");
    let signature = identity.signing_key.sign(message.as_bytes());

    let url = format!(
        "{}/api/v1/enrollment-requests/{}?timestamp={timestamp}&signature_hex={}",
        server_url.trim_end_matches('/'),
        request_id,
        hex::encode(signature.to_bytes()),
    );
    let response = ureq::get(&url).call()?;
    let body = response.into_string().map_err(|e| EnrollError::Http(e.to_string()))?;
    serde_json::from_str(&body).map_err(Into::into)
}

/// The enrollment transaction (§7.2, unattended/admin-approval mode):
/// ensure this device key has an ACCEPTED enrollment, returning the
/// server-assigned device_id for check-ins. Blocks, polling, while the
/// request is pending (the demo/admin step). Rejected → terminal error
/// (§7.3); the admin must clear the request server-side.
pub fn ensure_enrolled(
    server_url: &str,
    identity: &DeviceIdentity,
    state_dir: &Path,
    proposed_device_id: &str,
) -> Result<String, EnrollError> {
    ensure_enrolled_with_interval(
        server_url,
        identity,
        state_dir,
        proposed_device_id,
        Duration::from_secs(5),
    )
}

/// The transaction body with an injectable poll interval (tests use a short
/// one; production polls every 5s so admin approval feels immediate).
pub fn ensure_enrolled_with_interval(
    server_url: &str,
    identity: &DeviceIdentity,
    state_dir: &Path,
    proposed_device_id: &str,
    poll_interval: Duration,
) -> Result<String, EnrollError> {
    let record_path = state_dir.join("enrollment.json");

    // Already accepted on a previous boot? The record is the cache.
    if let Ok(bytes) = std::fs::read(&record_path) {
        if let Ok(record) = serde_json::from_slice::<EnrollmentRecord>(&bytes) {
            return Ok(record.device_id);
        }
        // Corrupt record: fall through and re-run the transaction; the
        // server-side idempotency resolves it.
    }

    let hardware = read_hardware_identity();
    eprintln!(
        "oma-id-agent: device not enrolled — requesting enrollment ({} public key {})",
        hardware.device_name.as_deref().unwrap_or("unnamed"),
        identity.public_key_hex
    );
    let request_id = post_request(server_url, identity, &hardware, proposed_device_id)?;
    eprintln!(
        "oma-id-agent: enrollment request {} pending — waiting for administrator approval",
        request_id
    );

    // Poll until an administrator resolves the request. The device-signed
    // poll proves key possession (§7.2 step 4); the poll interval is short
    // so the admin UI feels immediate during enrollment.
    loop {
        let parsed = poll_status(server_url, request_id, identity)?;
        match (parsed.state.as_str(), parsed.device.as_ref()) {
            ("accepted", Some(device)) => {
                let record = EnrollmentRecord {
                    request_id,
                    device_id: device.device_id.clone(),
                    accepted_at: now_secs(),
                };
                let record_bytes = serde_json::to_vec_pretty(&record).map_err(EnrollError::Json)?;
                persist_atomically(&record_path, &record_bytes)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&record_path, std::fs::Permissions::from_mode(0o600))?;
                }
                eprintln!(
                    "oma-id-agent: enrollment accepted — device id '{}' assigned",
                    device.device_id
                );
                return Ok(device.device_id.clone());
            }
            ("accepted", None) => {
                return Err(EnrollError::Message(
                    "server accepted the enrollment but sent no device id".into(),
                ))
            }
            ("rejected", _) => return Err(EnrollError::RejectedByAdmin(request_id)),
            ("pending", _) => {}
            (other, _) => {
                return Err(EnrollError::Message(format!(
                    "server reported unknown enrollment state '{other}'"
                )))
            }
        }
        std::thread::sleep(poll_interval);
    }
}
