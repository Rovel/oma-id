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

use oma_id_agent::{
    active_lease_in, apply_check_in, check_in, AgentConfig, AgentError, CheckInError, DeviceIdentity,
};
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
         \x20 server_url, device_id (proposed name), state_dir, socket_path,\n\
         \x20 check_in_interval_seconds (default 300)\n\
         \n\
         The device key pair lives in <state_dir>/device.key (0600) and is\n\
         generated on first boot. ENROLLMENT (plan §7.2, P3-a): the agent\n\
         posts its public key and hardware identity (manufacturer/model/\n\
         serial from DMI) to the server and waits for an administrator to\n\
         accept the request in the enrollment-review UI; the assigned\n\
         device id is persisted, then check-ins begin. Re-enrollment after\n\
         rejection needs the admin to clear the request."
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
    // there is no lease and the PAM surface stays unavailable. A 401 means
    // the device is not enrolled (or its key is unknown): run the P3-a
    // enrollment transaction (§7.2), which blocks until an administrator
    // accepts the request in the trusted browser.
    let mut store = Store::load(&config.store_path())?;
    let effective_device_id = Arc::new(RwLock::new(config.device_id.clone()));
    let response = match check_in(&config.server_url, &config.device_id, &identity) {
        Ok(response) => response,
        Err(CheckInError::Rejected { status: 401, .. }) => {
            let assigned = oma_id_agent::enrollment::ensure_enrolled(
                &config.server_url,
                &identity,
                &config.state_dir,
                &config.device_id,
            )
            .map_err(|e| AgentError::Message(format!("enrollment: {e}")))?;
            *effective_device_id.write().expect("device id lock") = assigned.clone();
            check_in(&config.server_url, &assigned, &identity)
                .map_err(|e| AgentError::Message(format!("initial check-in: {e}")))?
        }
        Err(error) => return Err(AgentError::Message(format!("initial check-in: {error}"))),
    };
    let hwm = apply_check_in(&mut store, &response, &config.key_set_path())?;
    eprintln!(
        "oma-id-agent: check-in ok (hwm={hwm}, leases={})",
        store.lease_count()
    );

    // §8.1: credential verification + §9.1 binding. The provisioned username
    // comes from the check-in response's POSIX mapping (the mapping exists
    // only when the server provisioned the person).
    let provisioned_username = response
        .posix
        .as_ref()
        .map(|p| p.username.clone());
    if let Some(username) = &provisioned_username {
        // Provision the local account from the server mapping (§8.4):
        // idempotent, collision-checked.
        let mapping = response
            .posix
            .clone()
            .expect("posix mapping just read");
        if let Err(error) = oma_id_agent::provisioning::ensure_local_account(&mapping) {
            eprintln!("oma-id-agent: local account provisioning failed (fail closed): {error}");
            return Err(AgentError::Message(format!(
                "local account provisioning: {error}"
            )));
        }
        eprintln!(
            "oma-id-agent: local account provisioned/verified: {username}"
        );
    }
    let verifier = Arc::new(oma_id_agent::provisioning::CredentialVerifier::new());

    let shared_store = Arc::new(RwLock::new(store));
    let shared_verifier = Arc::new(verifier);
    let shared_username = Arc::new(provisioned_username);
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
            let device_id = effective_device_id.read().expect("device id lock").clone();
            match check_in(&config.server_url, &device_id, &identity) {
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
    // A closure view of the verifier (ServiceConfig wants &dyn Fn).
    let verifier_fn = |local_username: &str, password: &str| {
        shared_verifier.verify(local_username, password)
    };

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
        let (lease, floor, not_before) = match active_lease_in(&store, now) {
            Some(lease) => {
                let floor = store
                    .high_water_revocation_epoch()
                    .min(lease.revocation_epoch);
                let nb = lease.not_before;
                (lease, floor, nb)
            }
            None => {
                expired.revocation_epoch = store.high_water_revocation_epoch();
                let nb = expired.not_before;
                (expired.verified_lease(), store.high_water_revocation_epoch(), nb)
            }
        };
        let config = ServiceConfig {
            socket_path: &shared_config.socket_path,
            lease,
            trusted_time_floor: not_before,
            minimum_revocation_epoch: floor,
            expected_credential: None,
            bound_local_username: shared_username.as_deref(),
            credential_verifier: Some(&verifier_fn),
        };
        handle_connection(&mut stream, &config);
    }
    Ok(())
}
