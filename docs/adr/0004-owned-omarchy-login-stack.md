# ADR-0004: Own the narrow Omarchy login stack

Status: accepted on 2026-09-05 by the project owner.

## Decision

OMA-ID will not use authd as a production runtime dependency. The supported
endpoint is Omarchy, so OMA-ID will own a deliberately narrow native stack:

- `oma-id-agent`, a Rust daemon that manages enrollment state, device identity,
  local authorization leases, credential verification and policy decisions;
- `pam_oma_id`, a thin PAM client that asks the agent to authenticate and to
  authorize the requested PAM account operation over a root-owned Unix socket;
- provisioned local Unix accounts with durable, server-recorded UID/GID mappings;
- a separate enrollment/pre-login UI for browser or device authorization; and
- an independent local recovery administrator and documented rollback path.

Rails remains the authoritative identity, enrollment and policy server. Neither
Rails nor an OIDC exchange runs inside a PAM module. The PAM module contains no
policy engine, credential database, HTTP client or remotely supplied scripting.

OMA-ID will not implement NSS initially. Assigned users are provisioned as real
local accounts before login. Adding NSS requires a demonstrated use case and a
new security and lifecycle review.

authd remains useful as reviewed comparative evidence for PAM conversations,
offline behavior, privilege separation, testing and failure recovery. Existing
P0 source/build findings remain in the repository but no longer block the chosen
native implementation.

## Reasons

The selected product boundary is one Rails issuer and one Omarchy desktop stack,
including its Quickshell locker. authd brings a general daemon/broker/NSS model,
Ubuntu-oriented packaging and policy choices that OMA-ID would still have to
adapt. Provisioning local users removes the dynamic identity lookup requirement
and gives OMA-ID one place to enforce its device-bound offline lease.

Quickshell's current password PAM context forwards the pending password when PAM
requests a response. It is not an adequate surface for browser URLs, QR codes or
multi-step enrollment. First authorization and account provisioning therefore
occur outside PAM; normal login and unlock use the resulting local credential.

## Required constraints

- Never invent cryptographic primitives. Use reviewed libraries and explicit key
  formats once signed lease verification is implemented.
- Authentication and account authorization are separate decisions. A correct
  cached password cannot override an expired or revoked authorization lease.
- The agent must fail closed for malformed state, wrong device/subject, rollback
  of trusted time, unsupported operation, stale revocation epoch or agent failure.
- Local credentials, refresh material and device keys must not appear in logs,
  process arguments or world-readable files.
- Account creation, UID/GID allocation, home ownership and group membership must
  be atomic, collision checked, idempotent and recoverable.
- PAM, SDDM, Quickshell, TTY, sudo/polkit and SSH behavior must be tested in a
  disposable Omarchy guest before a native login gate passes.
- Package upgrade, uninstall and rollback must preserve a working recovery path.

## First P0 proof

Build and test the pure lease-decision core without host privileges. Then connect
it to a fake Unix-socket agent and PAM test harness inside disposable Arch. Only
after those tests pass should a package install into a disposable Omarchy guest.

The proof must cover allow, expiry, explicit disablement, wrong device, wrong
person, unsupported operation, stale epoch, clock rollback, corrupt state, daemon
absence and recovery. It must not modify the development host's PAM stack.
