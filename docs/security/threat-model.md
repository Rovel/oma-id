# Initial threat model

Status: proposed controls, not implemented guarantees. Scope: P0 and the first
organization-owned, standard-user workstation profile. Unrestricted local root
and physical rollback defeat ordinary software-only enforcement.

## Assets and boundaries

Human browser → Rails issuer: identity, MFA, sessions, app authorization.
Installer → enrollment service: server trust, human approval, unique device key.
Device → management API: device-scoped credentials and lifecycle authorization.
Agent → root helper: authenticated local IPC and independently validated typed actions.
PAM/locker → `pam_oma_id` → local agent: credential authentication plus an
explicit authorization-lease decision over a root-owned Unix socket.
Rails → signing/recovery services: separate purposes, access policies, audit.
Build/release infrastructure → workstation: independently trusted signed artifacts.

## Threats and required evidence

| Threat | Required control | Acceptance evidence |
|---|---|---|
| Invitation theft/replay | Expiry, limited use, atomic key-bound approval | E04/E05, concurrent redemption |
| Network attacker or malicious issuer URL | HTTPS trust, constrained redirects/egress, no executable metadata | E06, SSRF and TLS negatives |
| Standard user seeks root | Narrow helper IPC; no wheel/container-socket defaults | E13/E21, peer and input substitution |
| Stolen administrator session | Step-up and scoped permissions; independent high-impact approval | Unauthorized recovery/publish attempts |
| Cross-person/device/organization substitution | Ownership constraints and per-object authorization | E22 across tokens, workers, exports |
| Compromised device key | Device-only scope, lifecycle check, rotation/revocation | E18/E20, no fleet enumeration |
| Disabled offline user | Device-bound expiring authorization, tested consumer hooks | E09–E14, explicit residual window |
| Stolen/corrupt local credential store | Reviewed password hashing, protected storage, atomic writes, strict parsing and rate limits | Offline brute-force, corruption, rollback and secret-log tests |
| Clock rollback/snapshot clone | Protected freshness state or online revalidation | E17, restart and rollback tests |
| Compromised Rails or signer | Separate key purposes, external audit, bounded operations | Independent release/approval boundary review |
| Malicious update or broken PAM | Signed coherent updates, canaries, verified rescue | E15/E16/E18 |
| Lost disk/authenticator/control plane | Separate recovery methods and restoration procedures | E19/E23, actual unlock/restore |
| Wrong support target | Bound target/generation, visible consent, expiry | E24, cancellation and target substitution |

## Key inventory (proposed)

| Material | Owner/location | Rotation or recovery requirement |
|---|---|---|
| OIDC signing key | Dedicated issuer key reference | JWKS overlap and retired-key rejection |
| Device private key/certificate | Per-device protected storage / constrained CA | Proof of key, renewal overlap, revoke generation |
| CA root / intermediate | Offline root / constrained issuance service | Independent backup and chain transition |
| Policy signing key | Policy service boundary | Versioned trust and expiry; no release-key reuse |
| Software release key | Independently controlled release pipeline | Revoked release and trust-root update rehearsal |
| Recovery wrapping key | Separately authorized recovery service | Restore independently of Rails; audit disclosure |
| Disk unlock / recovery secret | User-local secret / per-device encrypted escrow | Never log or upload user passphrase; verify rescue |

Open decisions: offline duration approval (24h is only proposed), hardware trust,
POSIX mapping ownership, privileged-helper operation catalog, signing custody,
recovery custodians, and project distribution license. Independent security review
is still required before production use.
