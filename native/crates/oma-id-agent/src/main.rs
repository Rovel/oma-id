//! The OMA-ID endpoint agent binary (P2 slice).
//!
//! Config file (JSON):
//! {
//!   "server_url": "https://id.example.org",
//!   "device_id": "workstation-12",
//!   "state_dir": "/var/lib/oma-id",
//!   "socket_path": "/run/oma-id/agent.sock",
//!   "check_in_interval_seconds": 300
//! }
//!
//! On boot: load or create the device key (prints the public key once when
//! generated, for out-of-band registration), load the lease store, check in
//! immediately, then serve the PAM socket while re-checking in on an
//! interval (§11.2). Every check-in response is verified (lease signatures
//! against the pinned issuer key set, ADR-0005) before leases are recorded.
//!
//! NOT yet production: no provisioning of local accounts, no revocation
//! polling beyond the epoch carried in check-ins, no supervision. Those are
//! later slices (plan §21 P4/P6).

use oma_id_agent::{active_lease_in, apply_check_in, check_in, AgentConfig, AgentError, DeviceIdentity};
use std::path::Path;
use oma_id_agent_daemon::{bind, handle_connection, ServiceConfig};
use oma_id_agent_store::{LeasePayload, Store};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => match run(args.get(1)) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("oma-id-agent: {error}");
                std::process::ExitCode::FAILURE
            }
        },
        Some("--help") | Some("-h") | None => {
            print_help();
            std::process::ExitCode::SUCCESS
        }
        _ => {
            print_help();
            std::process::ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "oma-id-agent — OMA-ID endpoint agent (P2 slice)\n\
         \n\
         USAGE:\n\
         \x20 oma-id-agent run --config <path>\n\
         \n\
         CONFIG (JSON):\n\
         \x20 server_url, device_id, state_dir, socket_path,\n\
         \x20 check_in_interval_seconds (default 300)\n\
         \n\
         The device key pair lives in <state_dir>/device.key (0600) and is\n\
         generated on first boot; register the printed public key with\n\
         `bin/rails oma_id:register_device[email,device_id,public_key_hex]`."
    );
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run(args: Option<&String>) -> Result<(), AgentError> {
    // args = the value after `run --config` (keep the flag-pair shape).
    let _ = args;
    let config_path = std::env::args()
        .skip_while(|arg| arg != "--config")
        .nth(1)
        .ok_or_else(|| AgentError::Message("run requires --config <path>".into()))?;
    let config = AgentConfig::load(Path::new(&config_path))?;
    eprintln!("oma-id-agent: config loaded ({config_path})");
    let identity = DeviceIdentity::load_or_create(&config.device_key_path())
        .map_err(|e| AgentError::Message(format!("device identity ({}): {e}", config.device_key_path().display())))?;
    eprintln!("oma-id-agent: device identity ready (pub {})", identity.public_key_hex);

    // First boot: print the public key for out-of-band registration (§6.3).
    if !config.key_set_path().exists() {
        eprintln!(
            "oma-id-agent: device public key (register with the issuer): {}",
            identity.public_key_hex
        );
    }

    // Initial check-in: fail closed — without a successful first check-in
    // there is no lease and the PAM surface stays unavailable.
    let mut store = Store::load(&config.store_path())?;
    let response = check_in(&config.server_url, &config.device_id, &identity)
        .map_err(|e| AgentError::Message(format!("initial check-in: {e}")))?;
    let hwm = apply_check_in(&mut store, &response, &config.key_set_path())?;
    eprintln!(
        "oma-id-agent: check-in ok (hwm={hwm}, leases={})",
        store.lease_count()
    );

    let shared_store = Arc::new(RwLock::new(store));
    let shared_config = Arc::new(config);

    // Check-in loop (§11.2): refresh leases + key set on an interval.
    {
        let store = Arc::clone(&shared_store);
        let config = Arc::clone(&shared_config);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(
                config.check_in_interval_seconds.max(30),
            ));
            let Ok(identity) = DeviceIdentity::load_or_create(&config.device_key_path()) else {
                eprintln!("oma-id-agent: device identity reload failed");
                continue;
            };
            match check_in(&config.server_url, &config.device_id, &identity) {
                Ok(response) => {
                    let Ok(mut guard) = store.write() else { continue };
                    match apply_check_in(&mut guard, &response, &config.key_set_path()) {
                        Ok(hwm) => eprintln!("oma-id-agent: check-in ok (hwm={hwm})"),
                        Err(error) => eprintln!("oma-id-agent: check-in apply failed: {error}"),
                    }
                }
                Err(error) => {
                    // §9.2: network errors never extend permissions; the
                    // existing store lease simply ages out.
                    eprintln!("oma-id-agent: check-in failed (permissions unchanged): {error}");
                }
            }
        });
    }

    // The accept loop: each connection gets a snapshot of the current store.
    let listener = bind(&shared_config.socket_path)?;
    eprintln!(
        "oma-id-agent: serving PAM socket {}",
        shared_config.socket_path.display()
    );
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let Ok(store) = shared_store.read() else { continue };
        let now = now_secs();

        // With an active lease the decision path authorizes normally; with
        // none, an empty expired lease still routes the request through the
        // real decision path so every denial is opaque and correctly framed.
        // The fallback payload must outlive the borrow, so it is declared
        // before the match.
        let mut expired = LeasePayload {
            subject_id: String::new(),
            device_id: String::new(),
            not_before: 0,
            expires_at: 0,
            revocation_epoch: 0,
            operations: vec![],
        };
        let (lease, floor) = match active_lease_in(&store, now) {
            Some(lease) => {
                let floor = store
                    .high_water_revocation_epoch()
                    .min(lease.revocation_epoch);
                (lease, floor)
            }
            None => {
                expired.revocation_epoch = store.high_water_revocation_epoch();
                (expired.verified_lease(), store.high_water_revocation_epoch())
            }
        };
        let config = ServiceConfig {
            socket_path: &shared_config.socket_path,
            lease,
            trusted_time_floor: floor,
            minimum_revocation_epoch: floor,
            expected_credential: None,
        };
        handle_connection(&mut stream, &config);
    }
    Ok(())
}
