//! P0 test harness only: runs the fake root-owned agent service with a
//! lease supplied on the command line. NOT a production daemon — no lease
//! store, signature verification, revocation polling, or supervision. The
//! production agent obtains verified leases from its own trust chain.

use oma_id_agent_core::{Operation as CoreOperation, VerifiedLease};
use oma_id_agent_daemon::ServiceConfig;
use std::path::PathBuf;
use std::process::ExitCode;

struct Args {
    socket: PathBuf,
    subject: String,
    device: String,
    not_before: u64,
    expires_at: u64,
    revocation_epoch: u64,
    trusted_time_floor: u64,
    minimum_revocation_epoch: u64,
    ops: Vec<CoreOperation>,
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
        subject,
        device,
        not_before,
        expires_at,
        revocation_epoch,
        trusted_time_floor,
        minimum_revocation_epoch,
        ops,
        password,
    })
}

fn main() -> ExitCode {
    let args = match parse(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("fake-agent: {message}");
            return ExitCode::FAILURE;
        }
    };

    let lease = VerifiedLease {
        subject_id: &args.subject,
        device_id: &args.device,
        not_before: args.not_before,
        expires_at: args.expires_at,
        revocation_epoch: args.revocation_epoch,
        operations: &args.ops,
    };
    // `password` is owned by Args and outlives the config; borrow it.
    let expected_credential = args.password.as_deref();
    let config = ServiceConfig {
        socket_path: &args.socket,
        lease,
        trusted_time_floor: args.trusted_time_floor,
        minimum_revocation_epoch: args.minimum_revocation_epoch,
        expected_credential,
    };
    if let Err(error) = oma_id_agent_daemon::serve(&config) {
        eprintln!("fake-agent: {error:?}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
