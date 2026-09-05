# Native baseline discovery — 2026-09-05

Status: source inspection, comparative authd build, and owned-agent foundation.
No native login gate
has passed. The local `../omarchy` checkout is clean and matches inventory commit
`493067741e081c3b09082da6bfd51e99ec24ef00`.

| Surface | Observed source | Required experiment |
|---|---|---|
| Lock entry | `bin/omarchy-system-lock` calls `omarchy-shell lock lock` | Real Quickshell lock/unlock |
| Password lock | `shell/plugins/lock/Service.qml` uses `omarchy-lock-password`; responds to requested prompts with the pending password | Broker selection/device prompts, cancellation, errors, non-root PAM execution |
| Fingerprint lock | Separate `omarchy-lock-fingerprint` PAM context | Account-policy enforcement after biometric success, offline disablement |
| PAM configuration | `bin/omarchy-apply-lock` includes `system-local-login` for account handling in both stacks | Establish whether the actual consumer invokes account management; configuration alone is insufficient |
| Owner privilege | `bin/omarchy-provision-owner` grants wheel and configures sudo | Managed user must not inherit owner privileges |
| Autologin | Provisioning keeps autologin on encrypted installations; one-time on unencrypted installations | Explicit managed baseline and alternate-login bypass checks |
| Keyring | `install/user/default-keyring.sh` creates a default keyring; SDDM setup removes GNOME keyring PAM hooks | Secret storage and recovery policy |

Do not execute those installation scripts on the development host. Hyprlock is
an older assumed profile, not the locker in the selected source baseline.

## Available isolation

The development host is WSL2; no host QEMU or `/dev/kvm` was found. Docker Desktop
provides Linux containers, also without `/dev/kvm` in the inspected container.
The owner offered a disposable Arch WSL distro; its name is not yet supplied.
Such a distro can validate packaging and service integration, but does not by
itself prove the selected desktop's graphical, firmware, or recovery paths.

The upstream ISO acceptance runner requires KVM (`-enable-kvm`, `-cpu host`).
Its dependency installer must not be run on this host. A separate VM runner or
an explicitly adapted software-emulated guest is still required.

## Superseded comparative authd build

`tests/arch/Dockerfile` pins the official Arch image digest and the 2026-09-04
Arch archive repository. `scripts/prepare-arch-context.py` verifies the captured
authd archive against `baseline.json` before creating the Docker input context.
The context uses gzip/GNU tar: the first PAX-format attempt was interpreted as
a Dockerfile by the Windows Docker stdin path and failed before compilation.

```sh
python3 scripts/prepare-arch-context.py
docker build --progress plain -t oma-id-p0-arch - < .cache/p0/arch-context.tar.gz
```

The build script records package versions, toolchains and separate exit/log
results for daemon, CLI, PAM generation/client, NSS, broker and selected tests.
No host mounts, host PAM changes, production identities or privileged container
are needed. Compilation success is not PAM/NSS integration or login evidence.

Latest container result (`oma-id-p0-authd-build`, retained after exit):

| Step | Result | Finding |
|---|---:|---|
| authctl | pass | Built from pinned source |
| PAM client | pass | Built, but not installed or exercised through PAM |
| NSS | pass | Cargo release build completed |
| OIDC broker | pass | Built from nested broker module |
| Broker/provider tests | pass | Root tests were skipped by `AUTHD_SKIP_ROOT_TESTS=1` |
| authd daemon | blocked | Go module downloads timed out through the container network |
| PAM generation | blocked | `protoc-gen-go` was absent; generated artifacts were not created |

These results remain useful comparative evidence. ADR-0004 removed authd from
the production path, so its two build failures no longer block OMA-ID. Do not
spend P0 time completing this build unless a comparison is needed.

## Selected owned-agent foundation

`native/` now contains the Rust workspace and a privilege-free lease-decision
core. The first contract binds a verified lease to immutable person and device
IDs, an explicit operation, validity bounds and a revocation epoch. It denies
clock rollback relative to the last authenticated server time. Signature parsing
and verification deliberately remain outside the core until a reviewed format
and library are pinned.

`mise run p0:agent-core` passes 35 tests (4 core, 7 IPC, 2 daemon unit,
9 socket integration, 3 PAM-client unit, 6 PAM-client integration, 4
PAM-module unit) on Rust 1.88.0. The workspace has no third-party crates
beyond pinned `libc`, `serde` and `serde_json`; `Cargo.lock` is committed as
reproducible input. Passing these tests establishes only decision semantics,
framing, peer policy and service mapping — not login enforcement.

### IPC protocol and peer policy (oma-id-agent-ipc)

Bounded length-prefixed JSON framing (4 KiB cap enforced before allocation),
correlated request ids, strict username grammar, `SO_PEERCRED` peer identity,
and read/write timeouts. Peer policy: root callers are limited to the valid
consumer/operation pairs; a non-root caller may only ask Quickshell for Unlock
for its own UID (resolved from a trusted local account lookup, never the
request body).

### Fake root-owned socket service (oma-id-agent-daemon)

`serve()` binds a `0o600` Unix socket and maps each connection through
peer identity → local account lookup → peer policy → lease core. Denial mapping
is deliberately opaque: unknown accounts, peer-policy failures and every lease
denial all answer `Deny(not_authorized)`; only protocol-level validation
failures answer `Deny(invalid_request)`, correlated when the body parsed.
Framing failures (size, EOF, malformed JSON) close the connection without a
reply. Integration tests prove: same-user Quickshell unlock allowed;
unprivileged consumer and unknown-account denials; expired-lease, clock-rollback,
stale-revocation-epoch and operation-scope denials; malformed/oversized frames
closed; daemon-down and unresponsive-daemon timeouts fail closed.

The service runs as the current (non-root) test user, so root-side behavior is
proven only by unit tests. This is a protocol stand-in: no lease store,
signature verification, revocation polling or supervision exists yet.

### Thin PAM client core (oma-id-pam-client)

Consumer-side core that `pam_oma_id` will wrap. `Client::authorize(consumer,
operation, local_username)` drives the real `exchange()` path with a random
16-byte request id from `/dev/urandom` and maps results to a fail-closed
`Outcome`: only an explicit `Allow` is `Authorized`; explicit denials are
`Denied`; daemon-down, timeout, protocol violation (wrong correlation id,
garbage frames, unsafe PAM usernames rejected before connecting) and missing
entropy are `Unavailable(reason)`. The PAM layer must treat everything except
`Authorized` as a block, so a valid local credential can never override an
expired, revoked, wrong-device or wrong-person lease. Integration tests run
against the fake service, including lying-agent correlation and garbage-frame
cases.

This is the Rust client core only: no libpam glue, no credential-exchange
message type, no PAM stage wiring yet.

### PAM module core (oma-id-pam-module)

`pam_oma_id` front end over the client core: `pam_sm_auth` and
`pam_sm_acct_mgmt` entry points read `PAM_SERVICE`/`PAM_USER` from the
handle via runtime-resolved `pam_get_item` (dlopen — no hard libpam link,
so it builds on any Linux host), map the service to a consumer/operation
pair, and translate the fail-closed outcome: only `Authorized` →
`PAM_SUCCESS`; denial → `PAM_AUTH_ERR` (auth) / `PAM_PERM_DENIED`
(account); unavailable → `PAM_SYSTEM_ERR`. The agent socket path is a
compile-time constant (`/run/oma-id/agent.sock`) with deliberately no
environment override, because the PAM environment is caller-influenced and
an overridable path would let a local attacker point the module at an
always-allowing agent. Unknown PAM services fail closed.

Host-side evidence: unit tests cover service mapping, outcome codes, and
the fixed socket path.

### Arch container build of pam_oma_id (disposable, pinned)

`tests/arch-pam/` + `scripts/prepare-arch-pam-context.py`: context exported
from committed tree ffbe03d7e5dbf186c8daec775b1949a8b1c9a0eb (tree
ccbf52664806b35bee1f65a768c4ef628627f0a6; source tarball sha256
dd36b78d11c56e5358591cdda7c47181c64ca37ff75549f244b2f9b0b21a28a9), image
`oma-id-p0-arch-pam:local` sha256:d65d4383… built from the same pinned
archlinux digest and 2026-09-04 repo snapshot as `tests/arch/`, rustc
1.98.0 (Arch package). Results in `.cache/p0/arch-pam-out/`:
`cargo test --locked` → 0 (all 35 tests), `cargo build --locked --release -p
oma-id-pam-module` → 0, artifact `pam_oma_id.so`
sha256:0ee4fc362c785298797eb29819653cf4b2f475f8977cdbbefab35ec229ecd1fe
exporting `pam_sm_auth` and `pam_sm_acct_mgmt`.

Exact failures found by the container run (all fixed, all recorded):
(1) `$USER` unset under docker failed 8 socket tests → tests now resolve
the username via `getpwuid(getuid())`; (2) root peer made Sddm/Login pass
peer policy in the harness → test branches on euid and asserts the lease
operation-scope denial; (3) the PAM-client denial anchor was
euid-dependent → re-anchored on Quickshell/Login, denied for every peer.

No real libpam load and no PAM consumer run yet: this is build + suite
evidence only.

### Next native slice

Real libpam consumer path in the same disposable Arch container: a small
PAM client harness (libpam `pam_start`/`pam_authenticate`) with an
`/etc/pam.d` service listing `pam_oma_id.so`, run against the fake agent
daemon on `/run/oma-id/agent.sock`; assert allow/deny/unavailable behavior
through real libpam and record exact results. Then the credential-exchange
message type once the authorization path is proven in a real consumer. No
login gate is claimed by any of the above.
