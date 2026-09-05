# P0 foundation findings

Status: in progress. P0 and release gates A–E have not passed.

## Recorded baseline

`baseline.json` records exact upstream commits, source-archive SHA-256 digests,
and published gem versions/dependency/license metadata. It is a discovery
inventory, not an assertion that branch HEAD equals the published gem source.
The protocol spike's `tests/interop/Gemfile.lock` records the resolved gem set.

| Component | Candidate / selection | Evidence and remaining work |
|---|---|---|
| Ruby | 4.0.6, local mise | `mise exec -- ruby -v` passes; selected by owner |
| Rails | 8.1.3.1 | In-process protocol harness boots on Ruby 4 |
| PostgreSQL | 18.6-bookworm, Compose named volume | Healthy; SQL version/database query passes; development-only superuser |
| Phlex / Rails integration | 2.4.1 / 2.4.0 | Owner-selected; resolved with Rails 8.1 |
| RubyUI | 1.6.0 | Owner-selected; resolved; asset/accessibility checks pending |
| Doorkeeper | 5.9.6 | Code/PKCE and replay lifecycle pass with explicit family adapter |
| OIDC extension | 1.10.5 | Device ID token and UserInfo pass; discovery adapter required |
| Device-grant extension | 1.0.3 | Lab adapter validates scopes and denial; polling/expiry/sequential redemption checked |
| WebAuthn | 3.4.3 | Resolved; authenticator/recovery tests pending |
| Omarchy / ISO | `quattro` commits in inventory | Local checkout matches pinned archive; ISO and package manifest unselected |
| OMA-ID native login | ADR-0004: Rust agent + thin PAM client + local users | Lease core, IPC framing/peer policy, fake root-owned socket service, and fail-closed PAM client core; libpam glue, credential exchange, provisioning and VM PAM evidence pending |
| authd comparison | Captured commit only | Partial Arch build retained as comparative evidence; not a runtime dependency |

Published metadata lists MIT for the captured Ruby gems; Omarchy and ISO root
licenses were inspected. This is not a transitive license audit. comparative authd
licenses, vendored code, package notices, and the project's distribution license
remain to be reviewed before distributing anything.

## Checks and limitations

- Source capture completed for ten repositories and eight gem metadata records.
- Local mise reports Ruby 4.0.6 and Bundler 4.0.16.
- `bundle lock` resolves the selected Rails/OIDC/UI dependencies on Ruby 4.
- `bundle install` completes: 9 direct dependencies and 84 gems in the workspace cache.
- All selected libraries load together on Ruby 4.0.6 and Rails 8.1.3.1.
- Compose PostgreSQL reports healthy; SQL reports PostgreSQL 18.6 and database
  `oma_id_development`. The service is left running for development.
- Docker Compose configuration validates. Docker Desktop works outside the
  execution sandbox; its Windows launcher fails inside the sandbox.
- Host-native QEMU and `/dev/kvm` were not available in the inspected environment.
  No VM login experiment was attempted; choose a disposable VM runner and media.
- [Protocol experiment](protocol-experiment.md): latest run is 40 tests / 269
  assertions with zero failures or skips. It includes durable family replay
  revocation, client/family isolation, PostgreSQL contention, audit rollback,
  fresh-process replay, algorithm substitution, host tampering and scope checks.
  Raw mode preserves the original dependency gaps; no default tests are skipped.
- Human authentication, enrollment, offline enforcement, and production deployment
  remain unverified.
- `mise run p0:agent-core` passes 31 Rust tests: lease decision semantics
  (valid use, person/device binding, validity boundaries, clock rollback,
  revocation epoch, operation scope), IPC framing/peer policy, the fake
  root-owned socket service (malformed frames, daemon-down, timeout, opaque
  denial mapping), and the thin PAM client core (explicit pass/deny, daemon-
down, timeout, lying-agent and unsafe-username fail-closed outcomes). Inputs
  are already-verified values; parsing, signatures, credentials, libpam glue,
  and account provisioning are not implemented yet. See
  [native-baseline.md](native-baseline.md).

## Next smallest implementation

Extend negative protocol coverage for client-role/grant confusion, persistent
polling slowdown, nonce substitution and concurrent code/device redemption.
The lab implementation of [ADR-0003](../adr/0003-refresh-family-replay.md) now has
concurrency, rollback and process-independence evidence; production review remains.
In the separate VM workstream, select media/hardware and establish the owned
agent/PAM → SDDM/Quickshell path using `tests/vm/README.md`.

P0 still needs exact ISO/package pins, agent credential/provisioning tests,
libpam glue over the thin PAM client core and real SDDM/Quickshell login evidence,
advisory/transitive license review, failure-state results, and an explicit
feasible/blocked decision for each critical path.

Trust boundaries changed by this foundation: local development DB only. No host
PAM, device accounts, production keys, or upstream repositories were modified.
