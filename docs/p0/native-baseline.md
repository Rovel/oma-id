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

The same fail-closed contract now covers `Client::exchange_credential`
(see the protocol-v2 section below). Still no libpam prompting glue or PAM
stage wiring.

### PAM module core (oma-id-pam-module)

`pam_oma_id` front end over the client core: `pam_sm_authenticate` and
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

### Real libpam consumer run (disposable, pinned)

Same pipeline, context at commit db8764698 (tree d508a992…, source
tarball sha256 e73f7086…), image `oma-id-p0-arch-pam:local`
sha256:933b58ab…, rustc 1.98.0 (Arch). `tests/arch-pam/pam-test-client.c`
is a minimal libpam client (`pam_start`/`pam_authenticate`/
`pam_acct_mgmt`, conv that never prompts); `/etc/pam.d/sddm` lists
`/out/pam_oma_id.so` for auth+account; the agent is the `fake_agent` P0
harness binary on `/run/oma-id/agent.sock`. All 8 result lines green:

cargo-test 0 (35 tests), build-module 0, compile-client 0,
scenario-valid 0 (`auth:0 acct:0`), scenario-expired 0 (`auth:7`,
PAM_AUTH_ERR explicit denial), scenario-down 0 (`auth:4`,
PAM_SYSTEM_ERR unavailable), scenario-unmapped 0 (`auth:4`, fail-closed
on unmapped service). Artifact `pam_oma_id.so`
sha256:f34d2420e1afe1b047152b420361ef1e215dad00c1e7a930d0baf3e925aa2bb6
exporting `pam_sm_authenticate` and `pam_sm_acct_mgmt`.

Exact failures found by the container run (all fixed, all recorded):
(4) C client used a nonexistent `pam_message_t` typedef → conv callback
takes `(int num_msg, const struct pam_message **, struct pam_response **, void *)`;
(5) exporting `pam_sm_auth` made libpam return PAM_MODULE_UNKNOWN (28)
without calling us — the auth entry point is `pam_sm_authenticate`
(pam_handlers.c);
(6) hand-written PAM constants were wrong: SYSTEM_ERR is 4 (not 1),
AUTH_ERR 7 (not 6), PERM_DENIED 6 (not 3);
(7) harness passed service name "oma-test" to `pam_start`, so
PAM_SERVICE was unmapped and every scenario failed closed before reaching
the agent — the consumer context is `sddm`.

Still no production PAM module install, no daemon lifecycle, no real
SDDM. This is a disposable-container protocol demonstration with a fake
agent; no login gate is claimed.

### Credential exchange on the wire (protocol v2)

The credential-exchange message type, host suite only (no container run yet
for this slice): `mise run p0:agent-core` → 45 tests / 0 failures.

- IPC (`oma-id-agent-ipc`): `PROTOCOL_VERSION` 1→2. One request frame is now
  a tagged union `AgentRequest` (`authorization` | `credential_exchange`),
  so a daemon can never mistake one exchange for the other; untagged v1
  frames fail to parse and the connection closes without a response. New
  `CredentialExchangeRequest` carries a typed, bounded credential
  (`Credential::Password`, ≤128 bytes, `MAX_CREDENTIAL_BYTES`); fingerprint/
  biometric material never crosses this channel. Response renamed
  `AgentResponse`; new `ProtocolError::CredentialTooLarge(usize)`.
- Daemon: `ServiceConfig.expected_credential: Option<&str>` (the fake agent
  takes it as optional `--password`; absent = every credential exchange
  denied). `decide_credential` keeps the same peer policy and unknown-
  account handling, compares in constant time, and never consults the lease —
  plan 9.1: a verified credential establishes the person, not the permission.
  Opaque denial preserved: wrong, empty, or unconfigured credential all map
  to `Deny(NotAuthorized)`; only structural validation fails map to
  `Deny(InvalidRequest)`.
- PAM client: `Client::exchange_credential(consumer, operation,
  local_username, password)` — forwarding only (no compare/store/log), same
  fail-closed `Outcome` mapping as authorization.
- New tests pin the separation: with an expired lease, the credential
  exchange still passes while the authorization request on the same service
  is denied. Also pinned: wrong/empty/unconfigured credentials are
  indistinguishable denials; oversized credential → correlated
  `InvalidRequest`; unknown tags and untagged v1 frames get no response.

Still no production PAM module install, no daemon lifecycle, no real SDDM;
no login gate is claimed by any of the above.

### Libpam prompt glue (protocol v2 container evidence)

`oma-id-pam-module` auth stage now runs the full consumer flow: ask the
conversation for a password (`PAM_PROMPT_ECHO_OFF` via dlsym-resolved
Linux-PAM extension `pam_prompt`, `<security/pam_ext.h>`), forward it with
`Client::exchange_credential`, then call `Client::authorize`; the pure
`authenticate_outcomes(credential, authorization)` decides the PAM code.
Both decisions are always taken (no short-circuit): a verified credential
never rescues a lease denial and vice versa — plan 9.1 made executable in
the container. The C harness conv answers ECHO_OFF prompts from
`$OMA_TEST_PASSWORD` (unset → `PAM_CONV_ERR`); the module under test never
reads the environment. Scenario matrix: valid / wrong / expired / down /
unmapped, with per-scenario `AGENT_PASSWORD` and `CLIENT_PASSWORD`.

Container run: context at commit af57df34017aab4dc96fd9e9b8e151f67cf81f2d
(tree f746bddb…, source tarball sha256 481bffb1…), image
`oma-id-p0-arch-pam:local` sha256:93c7b35b…, rustc 1.98.0 (Arch). All 8
result lines green in `.cache/p0/arch-pam-out/results.tsv`:

cargo-test 0 (46 tests), build-module 0, compile-client 0,
scenario-valid 0 (`auth:0 acct:0` — correct credential + valid lease pass
both stages), scenario-wrong 0 (`auth:7`, PAM_AUTH_ERR before the lease is
consulted), scenario-expired 0 (`auth:7` — correct credential passes the
exchange, expired lease denied by `authorize`; §9.1 separation proven in
the container), scenario-down 0 (`auth:4`, PAM_SYSTEM_ERR, agent absent),
scenario-unmapped 0 (`auth:4`, fail-closed before any prompt).
Artifacts: `pam_oma_id.so` sha256:220e98d628d81a141fee614272f5d37ba817cf2
cb83761dfade8bce632639d3e, `pam-test-client`
sha256:31b6ca92be649e69147f80a4262cf3fac6a43936993c866019d4dc89ef276ece.

Exact failures found by the container runs (all fixed, all recorded):
(8) conv wrote to `*resp` as if it were a single struct instead of filling
the allocated array → segfault; (9) hand-written Linux-PAM structs used
invented field names — 1.7 is `struct pam_message { int msg_style; const
char *msg; }` and `struct pam_response { char *resp; int resp_retcode; }`;
(10) `pam_prompt` is the extension API in `<security/pam_ext.h>`
(`int pam_prompt(pam_handle_t *, int style, char **response, const char
*fmt, ...)`, libpam allocates the response), not the printf-style helper
in `pam_misc/pam_prompt.h`.

Still no production PAM module install, no daemon lifecycle, no real SDDM;
the password in the container matrix is a test fixture, not a credential
store. No login gate is claimed.

### oma-id GitHub Actions CI (on push)

`.github/workflows/p0-native.yml`, two jobs:

1. `native-suite` — Rust 1.88.0, `cargo test --manifest-path native/Cargo.toml --locked`
   (same command as `mise run p0:agent-core`).
2. `arch-pam-container` — `scripts/prepare-arch-pam-context.py` (asserts clean
   tree, records commit/tree/source hashes) → docker build of the pinned Arch
   image → `docker run -d` + `docker wait` (build.sh exits nonzero on any
   failed step) → copy `/out/.` out → verify all 8 result lines are exactly
   `<step>\t0` and that the line count is 8 → record image digest + artifact
   sha256s → upload `.cache/p0/arch-pam-out/` as `arch-pam-evidence`
   (`if: always()`).

Actions: `actions/checkout@v7`, `actions/upload-artifact@v7` (node24),
`dtolnay/rust-toolchain@1.88.0` (the tag selects the toolchain; that release
predates the `toolchain` input — do not add a `with:` block).

First verified run: push of 7e7a8e6…/f81451a, run 34031972926 (2026-09-06):
both jobs success, zero annotations, artifact `arch-pam-evidence` uploaded.
Failures found and fixed by CI itself: (11) `tee .cache/p0/context-manifest.json`
raced the script's directory creation on a fresh runner → `mkdir -p .cache/p0`
in the workflow step; (12) node20 action versions + invalid `toolchain` input
warnings → bumped to node24 majors and dropped the input.

### omarchy-iso integration branch (oma-id-p0-standin)

Cross-fork integration per the recorded strategy: `oma-id-p0-standin` on
Rovel/omarchy-iso (commit cbfe8b1), pinning oma-id at
235fe091ee337e294d11cedb810370907eb602a2 (the commit that added
`tests/iso-smoke/run-smoke.sh`).

- `builder/oma-id-layer.sh` — gated layer: clone oma-id at `OMA_ID_SHA`,
  `cargo build --locked --release` (module + daemon), compile the C client,
  install `pam_oma_id.so` → `/usr/lib/security/`, harness + smoke under
  `/opt/oma-id/`, plus a `PROVENANCE` file (repo, SHA, subject, rustc,
  artifact sha256s). `builder/build-iso.sh` is untouched unless `OMA_ID_SHA`
  is set; **no PAM service on the ISO is modified** — the smoke script uses
  `omarchy-lock-password` (Quickshell/Unlock) as the mapped service so the
  real `sddm` entry is never touched, backs up any pre-existing file, and
  cleans up on exit.
- Smoke matrix (5 scenarios, real libpam, installed paths) runs two ways:
  locally pre-verified via docker cp (archlinux:latest digest sha256:82b1b08…
  — same pinned base as the P0 container — rustc 1.98.1, all lines green,
  exit 0) and in omarchy-iso Actions run 34049213475 (push of cbfe8b1):
  `packaging-smoke` job green, zero annotations, provenance artifact uploaded.
  `iso-build` correctly skipped on push (manual-dispatch only).
- oma-id CI also re-verified the pin commit: run 34048770222 green (46 tests).
- Full ISO build with the layer embedded: first verified green in run
  34049456445 (7.4G ISO uploaded). Log-based packaging evidence only — the
  squashfs was never independently inspected.

#### Incident + policy: artifact verification stays in CI

An attempt to verify the downloaded ISO artifact locally (7.9G zip →
7.4G ISO → squashfs extraction) exhausted the Windows host disk and
  crashed the machine: WSL2 vhdx files grow dynamically as Linux writes,
  so `df` inside WSL is meaningless for host-disk risk. Policy from here:
  heavy artifact handling (multi-GB extraction, chroot verification) runs
  only on disposable CI runner disks or non-system disks; locally, at most
  `gh run download` for a USB burn.

#### CI smoke on the installed live root (runs 34072614610 → 34074550877)

The ISO build job now runs the smoke **inside the build** via mkarchiso's
`customize_airootfs.sh` hook: mkarchiso installs the package set into its
work dir, overlays the layer files, then executes the hook via arch-chroot
in the fully installed live root, then deletes it. Gated by
`/opt/oma-id/.smoke-on-build` (`OMA_ID_SMOKE=1`) so plain layer builds stay
passive. `packaging-smoke` (every push) runs the matrix under **both**
bash and zsh — the Omarchy live root ships zsh as the live shell.

Failures found by CI in this iteration (all fixed, all recorded):
(13) the pre-mkarchiso `airootfs/` dir holds only customization files — the
OS is installed later inside mkarchiso's work dir, so a direct chroot there
found no shell at all; fixed by moving to the customize_airootfs hook.
(14) zsh has a read-only special variable `$status` — `local status` in the
smoke's `record()` aborted under zsh; renamed to `rc` (oma-id a5bc3c9).
(15) mkarchiso copies custom airootfs files with `cp --no-preserve=mode`
and only restores modes declared in the profile's `file_permissions` map —
the layer's binaries landed non-executable ("permission denied:
pam-test-client", fake_agent never bound); fixed by appending
`file_permissions+=(…)` to the working profiledef copy when OMA_ID_SHA is
set. Note: mkarchiso warns that customize_airootfs.sh is deprecated — if a
future archiso removes it, this hook needs a replacement.

Final verified state (run 34074550877, 2026-09-07, both jobs green): the
hook log shows all 5 scenarios with correct expected/actual codes
(`valid 0/0`, `wrong 7`, `expired 7`, `unmapped 4`, `down 4`) on the
installed live root, `oma-id smoke passed on the installed live root`,
mkarchiso Done, ISO artifact uploaded. This is the shipped airootfs
content, verified without touching any local disk.

### Next native slice

Selector end-to-end on the burnt machine: DONE (owner-executed 2026-09-07,
all green — see docs/p0/server-baseline.md). The §6.1/§6.2 consumer path is
proven end to end: burnt ISO → ownership choice → server validation →
Rails identity front. Remaining P0/P1 boundary work: LAN reachability from
other devices needs a one-time Windows Hyper-V/firewall allow (WSL mirrored
networking; commands recorded in docs/p0/server-baseline.md), then the
Rails identity foundation (people, admin bootstrap, authentication) and
agent-side lease store / trust-chain groundwork per oma-id_plan.md.
