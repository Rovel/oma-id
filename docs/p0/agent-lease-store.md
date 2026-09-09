# P0 agent slice: signed leases and the lease store

Status: agent-side trust-chain groundwork (P0/P1 bridge). Executed
2026-09-07. No production trust chain, key ceremony, or login gate is
claimed; the Rails issuer does not sign leases yet (next slice).

## What this slice is

The fake agent so far trusted command-line lease arguments — the lease was
never authenticated, so the §9.1 trust chain had no agent-side half. This
slice adds it:

1. **Signed leases** (`oma-id-agent-store`): `SignedLease` = the lease
   payload + an ed25519 signature over the payload's `serde_json` encoding
   (`ed25519-dalek` 2 — an established implementation; `verify_strict`).
   `Store::verify_all` re-checks every recorded signature on load, so a
   store file edited after recording fails closed (JSON validity alone is
   not trust).
2. **Durable store with anti-rollback** (plan §9.3): a single JSON store
   file (versioned, atomically written via tmp+rename, plan §12.3) holds the
   leases plus a **revocation-epoch high-water mark**. `record()` verifies
   the signature, rejects an incoming epoch older than the high-water mark
   (`RollbackDetected`), rejects already-expired leases, replaces the
   (subject, device) entry, bumps the high-water mark, and persists. A
   corrupt store fails closed on load; an unsupported store version is an
   error, never a silent reset.
3. **Store mode in the fake agent**: `fake_agent --store <path>
   --issuer-key <hex>` loads the store, verifies every signature against
   the pinned issuer key before binding the socket, selects the newest
   unexpired lease, and feeds the real socket authorization path. The
   CLI-lease mode remains for the established scenario scripts; mixing
   `--store` with CLI lease arguments is a hard error (one lease source).
   The store's high-water mark feeds `minimum_revocation_epoch`.
4. **Core untouched otherwise**: `oma-id-agent-core` only gains serde
   derives on `Operation` (the crate's purity contract — signature
   verification outside the core — is preserved; the store crate owns it).

## Tests (all executed locally, 2026-09-07)

`cargo test --locked` → **59 tests / 0 failures / 0 warnings** (was 46):
+11 store unit tests (sign/verify roundtrip, tampered payload, wrong issuer
key, record+reload, rollback detection and persistence, expired-at-record
rejection, same-subject replacement, corrupt store fail-closed, unsupported
version, key-length validation, post-record tamper caught by
`verify_all`), +2 daemon integration tests (signed-lease store authorizes
through the real socket path as a Quickshell/Unlock non-root peer;
tampered store file fails signature verification). Release profile builds
clean (`--release -p oma-id-pam-module -p oma-id-agent-daemon`).

## Boundaries and remaining work

- **Issuer key distribution/pinning is undecided** — needs an ADR before
  production (plan §5.3: lease-signing keys are a separate key purpose).
  Tests use fixed-seed keys; `issuer_keypair` exists for tooling only.
- **The Rails issuer does not sign leases yet.** The signed-payload
  encoding is this crate's `serde_json` output; the P2 cross-language
  contract (byte-identical canonical encoding from Rails, or a defined
  canonicalization) must be pinned before Rails signs anything.
- The store is a single-user JSON file: no fsync strategy, no multi-lease
  eviction policy beyond (subject, device) replacement, no concurrent-agent
  locking — deployment decisions (plan §13), recorded not solved.
- Rollback detection covers the revocation-epoch high-water mark; clock
  rollback detection stays in the core (`trusted_time_floor`) and
  persistent monotonic-time hardening is plan §9.3 future work.
- `fake_agent --store` is a harness: the production agent's check-in and
  renewal paths (P4) will own store refreshes.

## Next agent-side step

The Rails issuer mints signed leases (P2 contract: device flow → lease
issuance with the same payload schema), and the store's recorded
`standin-choice`/enrollment handoff grows into the real renewal path.

## Lease issuance endpoint (executed 2026-09-08)

The Rails server now issues leases: `POST /api/v1/device/leases`
(`server/app/controllers/api/v1/device_leases_controller.rb`), gated by a
bearer token (`OMA_ID_LEASE_TOKEN`; unset → 503 fail-closed, wrong → bare
401 — a lab stand-in for the §6.2 enrollment transaction, replaced in P3).
The issuer owns the revocation epoch: strictly increasing per (subject,
device) pair, persisted with every issuance (`IssuedLease` — the P0 audit
trail, plan §16). Validity is bounded: 60s clock skew, 24h maximum duration
(§9.2). The response IS the agent's store file (version, high-water mark,
lease record) plus the pinned issuer key — the output drops straight into
`fake_agent --store`.

Tests: +7 Rails request tests (21 runs / 71 assertions / 0 failures): 503
unconfigured, bare 401 wrong token, store-shape issuance with issuer-owned
epoch, per-pair epoch monotonicity, 24h bound, unknown operation +
oversized identifier rejections, malformed JSON.

**Live end-to-end (executed in a disposable container against the running
Rails server):** curl with the lab token → store file → `fake_agent --store
--issuer-key <pinned>` → PAM-style client → `auth:0 acct:0`; wrong
credential → `auth:7`; agent down → `auth:4`; wrong/missing token → 401.
The full §9.1 chain now runs over the network: Rails identity → signed
lease → agent store → real socket → PAM decision.

Boundaries: the bearer token is a lab stand-in for the enrollment
transaction; the issuer key is still lab seed material (ADR pending); the
epoch is per-(subject, device) with no global revocation broadcast yet
(the store's HWM enforces agent-side anti-rollback).

## Real agent daemon + device check-ins (P2 slice, executed 2026-09-08)

`oma-id-agent` (new crate + binary): the endpoint agent per §11.1/§11.2.
Device key pair in the state dir (0600, generated on first boot, public key
printed once for out-of-band registration), HTTPS check-ins signed with the
device key, check-in responses applied through the verified store path
(lease signatures against the ADR-0005 key set, anti-rollback HWM), issuer
key set distributed via check-in, PAM socket served from the live store.

Rails: `Device` model (technician pre-provisioning, §6.3),
`POST /api/v1/device/check-ins` (key-possession auth, ±300s replay window,
lease minting bound to the device's person, issuer key-set distribution,
check-in audit), `oma_id:register_device` task.

**Live end-to-end executed** (disposable container): agent boots → device
key generated → check-in 401 (unregistered, fail closed) → registered →
check-in ok (hwm increments across interval re-check-ins: 7→8) → store +
issuer-keys.json persisted → socket bound 0600 → **probe decision Allow**
with a server-minted lease.

**Honest boundary found by the live run**: the PAM flow's credential
exchange is denied (`auth:7`) with the real agent — the agent has no
credential store yet. §8.1 makes credential verification the agent's job
(against provisioned local accounts); that is the next slice. The lease
authorization path is fully proven (probe Allow); the credential path is
the recorded gap. Also found and fixed live: (20) the check-in epoch must
use `next_epoch_for` (the env-pinned epoch collided with the unique index
and 500'd); (21) the daemon's `bind` now creates the socket's parent
directory; (22) an expired/missing lease routes through the same decision
path (opaque denials, correct framing) instead of dropping the connection.

## Local account provisioning + credential verification (§8.1/§8.4, executed 2026-09-09)

The chain is now complete end to end. The server allocates a durable
`PosixIdentityMapping` at device registration (managed UID/GID range
10000-19999, derived safe username with reserved-name checks, §8.4); the
check-in response carries the mapping; the agent provisions the local
account via `useradd`/`groupadd` **as child processes with argument
arrays** (§12.3 — no shell concatenation), idempotently, rejecting uid/name
collisions instead of "fixing" them. Credential verification calls
**libxcrypt's `crypt(3)`** — the same implementation pam_unix uses — over
the shadow hash, constant-time compared; rate limiting (5 failures / 15 min
→ cooldown) is enforced per local username inside the agent (§5.1).

`unix_chkpwd` was evaluated first and rejected: it deliberately refuses
direct invocation by root (built only for the setuid transition with a
non-root real uid — an anti-oracle property), which makes it unusable for
the root agent. The daemon's `ServiceConfig` gained `bound_local_username`
(the lease authorizes exactly the provisioned account, §9.1) and
`credential_verifier` (the agent's own verifier replaces the stand-in
expected-credential).

**Live end-to-end (disposable container, privileged):** register device →
POSIX mapping `owner uid=10000` → agent check-in → **local account
provisioned** (`owner:x:10000:10000:Organization Owner:/home/owner:/bin/zsh`
+ user-private group + home) → PAM sign-in:
- correct local password → **`auth:0 acct:0`** (the complete chain: prompt →
  credential exchange verified via crypt(3) → Rails-signed lease
  authorization → PAM success)
- wrong password → `auth:7`
- wrong local username → `auth:7` (§9.1 binding)
- after 5 failed attempts, the CORRECT password is denied (rate limit)

The local password is a local/offline credential (§10): set locally
(chpasswd in the demo), never synced from any web credential. Failures
found and fixed live: (23) `groupadd --gid` needs the group NAME
(user-private group named after the account); (24) `unix_chkpwd` refuses
root invocation by design — crypt(3) FFI instead; (25) Arch's libxcrypt
soname is libcrypt.so.2 (host-built binary linked .so.1 — the packaging
slice builds on Arch properly; demo used a symlink).

## Packaging + ISO layer (executed 2026-09-09)

`packaging/arch/` (§23): `oma-id-agent.service` (systemd unit — Runtime/
StateDirectory, §11.1 hardening that still permits provisioning; the
P4 privileged-helper split enables stricter isolation later), the config
example, and a PKGBUILD (`oma-id-agent` + `pam-oma-id`) documenting the
package shapes from the pinned workspace. Repository publishing is P4/P8
with the §13 signing decisions.

The omarchy-iso layer (`oma-id-p0-standin` @ 0a51c3e) now ships the real
agent: `/usr/bin/oma-id-agent` + the systemd unit (enabled in the live
environment) + `/etc/oma-id-agent.json` (server UNCONFIGURED by default —
per-deployment data, set on the live machine; the dispatch-input route was
rejected to keep the LAN address out of public artifacts) + **the §8.2
PAM wiring**: `/etc/pam.d/sddm`, `omarchy-lock-password`,
`omarchy-lock-fingerprint` route auth+account through pam_oma_id.

**ISO build green** (run 34307434428, image `omarchy-2026.09.09-x86_64.iso`,
7.9G artifact): packaging-smoke (layer + bash/zsh smoke + selector
contract + agent fail-closed CI test) and iso-build (in-build smoke on the
installed live root) both green; provenance artifact confirms the layer
(agent + module + harness hashes, server UNCONFIGURED, device
workstation-1).

Upstream drift handled (loudly, never silent): (26) `broadcom-wl` was
removed from the Arch repos on 2026-09-09 — the build now drops
mirror-missing packages from BOTH the offline-mirror download and the
mkarchiso install list with per-package WARNINGs (nvidia-dkms also dropped
in the run).

**Remaining for the §8.2 matrix**: burn the ISO, boot on hardware, set
`/etc/oma-id-agent.json`, restart the service, register the printed device
key, and exercise the PAM services from the live environment (pam-test-client
+ the wired service files); the real SDDM/TTY/desktop login evidence needs
the INSTALLED system (the live ISO boots the console installer) — the
installed-system distribution is the P4 packaging step.
