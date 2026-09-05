//! Pure authorization-lease decisions for the OMA-ID endpoint agent.
//!
//! Parsing, signature verification, credential checking and PAM IPC stay outside
//! this crate. Callers may only construct a verified lease after those steps pass.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Login,
    Unlock,
    Elevate,
    RemoteLogin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Consumer {
    Sddm,
    Quickshell,
    Tty,
    Sudo,
    Polkit,
    Ssh,
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedLease<'a> {
    pub subject_id: &'a str,
    pub device_id: &'a str,
    pub not_before: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
    pub operations: &'a [Operation],
}

#[derive(Debug, Eq, PartialEq)]
pub struct Request<'a> {
    pub subject_id: &'a str,
    pub device_id: &'a str,
    pub consumer: Consumer,
    pub operation: Operation,
    pub now: u64,
    /// Last authenticated server time persisted by the agent.
    pub trusted_time_floor: u64,
    pub minimum_revocation_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denial {
    SubjectMismatch,
    DeviceMismatch,
    NotYetValid,
    Expired,
    ClockRollback,
    StaleRevocationEpoch,
    OperationNotAuthorized,
}

pub fn authorize(lease: &VerifiedLease<'_>, request: &Request<'_>) -> Result<(), Denial> {
    if lease.subject_id != request.subject_id {
        return Err(Denial::SubjectMismatch);
    }
    if lease.device_id != request.device_id {
        return Err(Denial::DeviceMismatch);
    }
    if request.now < request.trusted_time_floor {
        return Err(Denial::ClockRollback);
    }
    if request.now < lease.not_before {
        return Err(Denial::NotYetValid);
    }
    if request.now >= lease.expires_at {
        return Err(Denial::Expired);
    }
    if lease.revocation_epoch < request.minimum_revocation_epoch {
        return Err(Denial::StaleRevocationEpoch);
    }
    if !lease.operations.contains(&request.operation) {
        return Err(Denial::OperationNotAuthorized);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPS: &[Operation] = &[Operation::Login, Operation::Unlock];

    fn lease() -> VerifiedLease<'static> {
        VerifiedLease {
            subject_id: "person-1",
            device_id: "device-1",
            not_before: 1_000,
            expires_at: 2_000,
            revocation_epoch: 7,
            operations: OPS,
        }
    }

    fn request() -> Request<'static> {
        Request {
            subject_id: "person-1",
            device_id: "device-1",
            consumer: Consumer::Quickshell,
            operation: Operation::Unlock,
            now: 1_500,
            trusted_time_floor: 1_400,
            minimum_revocation_epoch: 7,
        }
    }

    #[test]
    fn permits_a_bound_unexpired_operation() {
        assert_eq!(authorize(&lease(), &request()), Ok(()));
    }

    #[test]
    fn denies_wrong_subject_and_device() {
        let mut candidate = request();
        candidate.subject_id = "person-2";
        assert_eq!(
            authorize(&lease(), &candidate),
            Err(Denial::SubjectMismatch)
        );
        candidate = request();
        candidate.device_id = "device-2";
        assert_eq!(authorize(&lease(), &candidate), Err(Denial::DeviceMismatch));
    }

    #[test]
    fn denies_time_boundary_and_clock_rollback() {
        let mut candidate = request();
        candidate.now = 999;
        candidate.trusted_time_floor = 900;
        assert_eq!(authorize(&lease(), &candidate), Err(Denial::NotYetValid));
        candidate = request();
        candidate.now = 2_000;
        assert_eq!(authorize(&lease(), &candidate), Err(Denial::Expired));
        candidate = request();
        candidate.now = 1_399;
        assert_eq!(authorize(&lease(), &candidate), Err(Denial::ClockRollback));
    }

    #[test]
    fn denies_stale_epoch_and_ungranted_operation() {
        let mut candidate = request();
        candidate.minimum_revocation_epoch = 8;
        assert_eq!(
            authorize(&lease(), &candidate),
            Err(Denial::StaleRevocationEpoch)
        );
        candidate = request();
        candidate.operation = Operation::Elevate;
        assert_eq!(
            authorize(&lease(), &candidate),
            Err(Denial::OperationNotAuthorized)
        );
    }
}
