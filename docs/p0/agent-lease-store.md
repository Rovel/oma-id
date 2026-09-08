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
