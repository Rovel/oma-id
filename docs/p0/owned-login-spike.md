# Owned login spike

Status: active P0 work following accepted ADR-0004.

## Boundary

The production path is:

```text
Rails enrollment/policy service
  → oma-id-agent (networked, unprivileged portion)
  → constrained local account helper
  → provisioned Unix account

SDDM / Quickshell / TTY / sudo / SSH
  → pam_oma_id
  → root-owned local agent socket
  → credential result AND authorization-lease result
```

The PAM request must never cause HTTP/OIDC traffic, account creation, policy
refresh, shell execution or a long interactive enrollment. Network refresh and
provisioning occur before the login transaction.

## Implemented

`native/crates/oma-id-agent-core` evaluates already-verified leases. It binds a
decision to subject, device, operation, validity interval and revocation epoch,
and rejects rollback below the last authenticated server time. Four unit tests
pass through `mise run p0:agent-core`.

This is deliberately not yet a signed lease parser. Naming the input
`VerifiedLease` prevents callers from presenting unverified bytes as policy.

## Next slices and exit evidence

| Slice | Evidence required before proceeding |
|---|---|
| Wire format and signature | Canonical encoding, strict size/version limits, pinned reviewed signature library, wrong-key/algorithm/device tests |
| Local IPC | Root-owned socket, peer credential checks, bounded message/time limits, malformed input and daemon-down tests |
| Credential store | Reviewed password hash, protected storage, rate limiting, atomic updates, no secret logging |
| Account helper | Typed operations only; UID/GID/name/path collision tests; idempotent create/update/disable and rollback |
| PAM test client | Authentication and account decisions mapped fail-closed in an isolated PAM harness |
| Omarchy guest | TTY, SDDM, Quickshell, sudo/polkit, SSH bypass, offline expiry, daemon failure and recovery evidence |

The local development host must never receive PAM configuration or managed test
accounts. Containers can test compilation and IPC; only a disposable system or
VM can establish PAM and desktop behavior.
