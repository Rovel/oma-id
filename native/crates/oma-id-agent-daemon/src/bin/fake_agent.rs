//! P0 test harness only: runs the fake root-owned agent service with a lease
//! supplied on the command line, or loaded from a signed-lease store.
//! NOT a production daemon — no signature rotation, revocation polling, or
//! supervision. The store mode consumes the signed-lease trust-chain
//! groundwork (`oma-id-agent-store`): every lease is verified against a
//! pinned issuer key before the service binds, and the store's revocation
//! high-water mark feeds the authorization floor (plan §9.3 anti-rollback).

use oma_id_agent_core::{Operation as CoreOperation, VerifiedLease};
use oma_id_agent_daemon::ServiceConfig;
use oma_id_agent_store::{IssuerKeySet, Store};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

enum LeaseSource {
    /// The original CLI-supplied (unsigned) lease — the pre-store harness
    /// mode, kept for the established scenario scripts.
    Cli,
    /// A signed-lease store verified against a pinned issuer key (single
    /// key — the pre-ADR-0005 compatibility mode).
    Store { path: PathBuf, issuer_key: String },
    /// A signed-lease store verified against a pinned issuer KEY SET with
    /// rotation states (ADR-0005). The preferred mode.
    StoreWithKeySet { path: PathBuf, key_set: PathBuf },
}

struct Args {
    socket: PathBuf,
    lease_source: LeaseSource,
    subject: Option<String>,
    device: Option<String>,
    not_before: Option<u64>,
    expires_at: Option<u64>,
    revocation_epoch: Option<u64>,
    trusted_time_floor: Option<u64>,
    minimum_revocation_epoch: Option<u64>,
    ops: Option<Vec<CoreOperation>>,
    password: Option<String>,
}

fn parse_ops(list: &str) -> Result<Vec<CoreOperation>, String> {
    let mut ops = Vec::new();
    for name in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        ops.push(match name {
            "Login" => CoreOperation::Login,
            "Unlock" => CoreOperation::Unlock,
            "Elevate" => CoreOperation::Elevate,
            "RemoteLogin" => CoreOperation::RemoteLogin,
            other => return Err(format!("unknown operation {other:?}")),
        });
    }
    if ops.is_empty() {
        return Err("no operations supplied".into());
    }
    Ok(ops)
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    value.parse().map_err(|_| format!("invalid number for --{name}"))
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut socket: Option<PathBuf> = None;
    let mut store: Option<PathBuf> = None;
    let mut issuer_key: Option<String> = None;
    let mut issuer_keys: Option<PathBuf> = None;
    let mut subject: Option<String> = None;
    let mut device: Option<String> = None;
    let mut not_before: Option<u64> = None;
    let mut expires_at: Option<u64> = None;
    let mut revocation_epoch: Option<u64> = None;
    let mut trusted_time_floor: Option<u64> = None;
    let mut minimum_revocation_epoch: Option<u64> = None;
    let mut ops: Option<String> = None;
    let mut password: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let (key, value) = match args.get(i + 1) {
            Some(v) => (args[i].as_str(), v.as_str()),
            None => return Err(format!("missing value for {}", args[i])),
        };
        i += 2;
        match key {
            "--socket" => socket = Some(PathBuf::from(value)),
            "--store" => store = Some(PathBuf::from(value)),
            "--issuer-key" => issuer_key = Some(value.into()),
            "--issuer-keys" => issuer_keys = Some(PathBuf::from(value)),
            "--subject" => subject = Some(value.into()),
            "--device" => device = Some(value.into()),
            "--not-before" => not_before = Some(parse_u64(value, "not-before")?),
            "--expires-at" => expires_at = Some(parse_u64(value, "expires-at")?),
            "--revocation-epoch" => {
                revocation_epoch = Some(parse_u64(value, "revocation-epoch")?)
            }
            "--trusted-time-floor" => {
                trusted_time_floor = Some(parse_u64(value, "trusted-time-floor")?)
            }
            "--min-revocation-epoch" => {
                minimum_revocation_epoch = Some(parse_u64(value, "min-revocation-epoch")?)
            }
            "--ops" => ops = Some(value.into()),
            // Optional: without it the agent has no credential material and
            // every credential exchange is denied (fail closed).
            "--password" => password = Some(value.into()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    let socket = socket.ok_or("missing required argument --socket")?;

    // Store mode: --store with --issuer-keys (ADR-0005 key set) or the
    // single-key --issuer-key compatibility mode; CLI lease args must not
    // be mixed in — one lease source, never two.
    if issuer_keys.is_some() && issuer_key.is_some() {
        return Err("--issuer-keys and --issuer-key are mutually exclusive".into());
    }
    match (store, issuer_keys, issuer_key) {
        (Some(path), Some(key_set_path), None) => {
            reject_mixed_cli_lease_args(&subject, &device, &not_before, &expires_at, &revocation_epoch, &trusted_time_floor, &minimum_revocation_epoch, &ops);
            Ok(Args {
                socket,
                lease_source: LeaseSource::StoreWithKeySet { path, key_set: key_set_path },
                subject: None,
                device: None,
                not_before: None,
                expires_at: None,
                revocation_epoch: None,
                trusted_time_floor: None,
                minimum_revocation_epoch: None,
                ops: None,
                password,
            })
        }
        (Some(path), None, Some(issuer_key)) => {
            reject_mixed_cli_lease_args(&subject, &device, &not_before, &expires_at, &revocation_epoch, &trusted_time_floor, &minimum_revocation_epoch, &ops);
            Ok(Args {
                socket,
                lease_source: LeaseSource::Store { path, issuer_key },
                subject: None,
                device: None,
                not_before: None,
                expires_at: None,
                revocation_epoch: None,
                trusted_time_floor: None,
                minimum_revocation_epoch: None,
                ops: None,
                password,
            })
        }
        (Some(_), None, None) => {
            Err("--store requires --issuer-keys (ADR-0005 key set) or --issuer-key (single key)".to_string())
        }
        (Some(_), Some(_), Some(_)) => {
            Err("--issuer-keys and --issuer-key are mutually exclusive".into())
        }
        (None, _, Some(_)) | (None, Some(_), None) => {
            Err("--issuer-keys/--issuer-key require --store".to_string())
        }
        (None, None, None) => {
            let subject = subject.ok_or("missing required argument --subject")?;
            let device = device.ok_or("missing required argument --device")?;
            let not_before = not_before.ok_or("missing required argument --not-before")?;
            let expires_at = expires_at.ok_or("missing required argument --expires-at")?;
            let revocation_epoch =
                revocation_epoch.ok_or("missing required argument --revocation-epoch")?;
            let trusted_time_floor =
                trusted_time_floor.ok_or("missing required argument --trusted-time-floor")?;
            let minimum_revocation_epoch =
                minimum_revocation_epoch.ok_or("missing required argument --min-revocation-epoch")?;
            let ops = parse_ops(&ops.ok_or("missing required argument --ops")?)?;
            Ok(Args {
                socket,
                lease_source: LeaseSource::Cli,
                subject: Some(subject),
                device: Some(device),
                not_before: Some(not_before),
                expires_at: Some(expires_at),
                revocation_epoch: Some(revocation_epoch),
                trusted_time_floor: Some(trusted_time_floor),
                minimum_revocation_epoch: Some(minimum_revocation_epoch),
                ops: Some(ops),
                password,
            })
        }
    }
}

/// The CLI lease arguments and store mode are mutually exclusive: one lease
/// source, never two.
fn reject_mixed_cli_lease_args(
    subject: &Option<String>,
    device: &Option<String>,
    not_before: &Option<u64>,
    expires_at: &Option<u64>,
    revocation_epoch: &Option<u64>,
    trusted_time_floor: &Option<u64>,
    minimum_revocation_epoch: &Option<u64>,
    ops: &Option<String>,
) {
    let present = [
        ("--subject", subject.is_some()),
        ("--device", device.is_some()),
        ("--not-before", not_before.is_some()),
        ("--expires-at", expires_at.is_some()),
        ("--revocation-epoch", revocation_epoch.is_some()),
        ("--trusted-time-floor", trusted_time_floor.is_some()),
        ("--min-revocation-epoch", minimum_revocation_epoch.is_some()),
        ("--ops", ops.is_some()),
    ];
    if let Some((name, _)) = present.into_iter().find(|(_, present)| *present) {
        eprintln!("fake-agent: --store must not be combined with {name}; the lease comes from the store");
        std::process::exit(2);
    }
}

/// Pick the newest unexpired lease from a store whose signatures were already
/// verified. Login first (the P0 consumer path), then the other operations.
fn active_lease_in(store: &Store, now: u64) -> Option<oma_id_agent_core::VerifiedLease<'_>> {
    store
        .active_lease(now, CoreOperation::Login)
        .or_else(|| store.active_lease(now, CoreOperation::Unlock))
        .or_else(|| store.active_lease(now, CoreOperation::Elevate))
        .or_else(|| store.active_lease(now, CoreOperation::RemoteLogin))
}

fn main() -> ExitCode {
    let args = match parse(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("fake-agent: {message}");
            return ExitCode::FAILURE;
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // The store must outlive every lease borrow below. `None` in CLI mode.
    let mut loaded_store: Option<Store> = None;
    let (lease, trusted_time_floor, minimum_revocation_epoch) = match &args.lease_source {
        LeaseSource::StoreWithKeySet { path, key_set } => {
            let key_set = match IssuerKeySet::load(key_set) {
                Ok(set) => set,
                Err(error) => {
                    eprintln!("fake-agent: issuer key set (fail closed): {error}");
                    return ExitCode::FAILURE;
                }
            };
            let store = match Store::load(path) {
                Ok(store) => store,
                Err(error) => {
                    eprintln!("fake-agent: store load (fail closed): {error}");
                    return ExitCode::FAILURE;
                }
            };
            let verifying = match key_set.active_key() {
                Ok((_, verifying)) => verifying,
                Err(error) => {
                    eprintln!("fake-agent: active issuer key: {error}");
                    return ExitCode::FAILURE;
                }
            };
            if let Err(error) = store.verify_all_with_key_set(&key_set, &verifying) {
                eprintln!("fake-agent: store verification (fail closed): {error}");
                return ExitCode::FAILURE;
            }
            let lease = match active_lease_in(&store, now) {
                Some(lease) => lease,
                None => {
                    eprintln!("fake-agent: no unexpired lease in the store authorizes any operation");
                    return ExitCode::FAILURE;
                }
            };
            // Anti-rollback floor (plan §9.3): never below the highest
            // revocation epoch this agent has persisted.
            let floor = store.high_water_revocation_epoch().min(lease.revocation_epoch);
            loaded_store = Some(store);
            let store = loaded_store.as_ref().expect("store just assigned");
            let lease = active_lease_in(store, now).expect("same store, same selection");
            let ttf = lease.not_before;
            (lease, ttf, floor)
        }
        LeaseSource::Store { path, issuer_key } => {
            let issuer = match oma_id_agent_store::issuer_verifying_key(issuer_key) {
                Ok(key) => key,
                Err(error) => {
                    eprintln!("fake-agent: pinned issuer key: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let store = match Store::load(path) {
                Ok(store) => store,
                Err(error) => {
                    eprintln!("fake-agent: store load (fail closed): {error}");
                    return ExitCode::FAILURE;
                }
            };
            if let Err(error) = store.verify_all(&issuer) {
                eprintln!("fake-agent: store verification (fail closed): {error}");
                return ExitCode::FAILURE;
            }
            let lease = match active_lease_in(&store, now) {
                Some(lease) => lease,
                None => {
                    eprintln!("fake-agent: no unexpired lease in the store authorizes any operation");
                    return ExitCode::FAILURE;
                }
            };
            // Anti-rollback floor (plan §9.3): never below the highest
            // revocation epoch this agent has persisted.
            let floor = store.high_water_revocation_epoch().min(lease.revocation_epoch);
            loaded_store = Some(store);
            let store = loaded_store.as_ref().expect("store just assigned");
            let lease = active_lease_in(store, now).expect("same store, same selection");
            let ttf = lease.not_before;
            (lease, ttf, floor)
        }
        LeaseSource::Cli => {
            debug_assert!(loaded_store.is_none(), "CLI mode never loads a store");
            let lease = VerifiedLease {
                subject_id: args.subject.as_deref().expect("cli subject"),
                device_id: args.device.as_deref().expect("cli device"),
                not_before: args.not_before.expect("cli not-before"),
                expires_at: args.expires_at.expect("cli expires-at"),
                revocation_epoch: args.revocation_epoch.expect("cli revocation-epoch"),
                operations: args.ops.as_deref().expect("cli ops"),
            };
            (lease, args.trusted_time_floor.expect("cli trusted-time-floor"), args
                .minimum_revocation_epoch
                .expect("cli min-revocation-epoch"))
        }
    };

    // `password` is owned by Args and outlives the config; borrow it.
    let expected_credential = args.password.as_deref();
    let config = ServiceConfig {
        socket_path: &args.socket,
        lease,
        trusted_time_floor,
        minimum_revocation_epoch,
        expected_credential,
        bound_local_username: None,
        credential_verifier: None,
    };
    if let Err(error) = oma_id_agent_daemon::serve(&config) {
        eprintln!("fake-agent: {error:?}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}