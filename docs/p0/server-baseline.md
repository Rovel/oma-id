# P0 server slice: Rails identity front (executed evidence)

Status: P0 lab slice. This records what was actually executed on 2026-09-07.
No login, enrollment, or offline gate is claimed; nothing here is production.

## What this slice is

`server/` is the first piece of the Rails application proposed in
`oma-id_plan.md` §23. It exists to close the remaining P0 item — "connect the
minimal Rails issuer and disposable Omarchy consumer paths" — by giving the
disposable Omarchy live environment (the `oma-id-p0-standin` ISO layer) a real
Rails service to reach over the LAN.

## Stack (pinned to the recorded baseline)

- Ruby 4.0.6 (local mise), Rails 8.1.3.1 — same pins as `tests/interop`
  (`docs/p0/baseline.json`, `server/Gemfile.lock`).
- Phlex 2.4.1 / phlex-rails 2.4.0, RubyUI 1.6.0 (ADR-001, ADR-0002).
- PostgreSQL 18.6-bookworm via `compose.yaml` (127.0.0.1 bind, named volume,
  development-only superuser). Databases: `oma_id_development`, `oma_id_test`.

## Implemented behavior

- `Organization` model (ADR-0004: one organization per deployment; unique,
  immutable-in-practice canonical `issuer`; display name and support contact
  are presentation data). Seeds refuse to change the issuer of an already
  seeded organization; `OMA_ID_ISSUER` sets it only on first seed.
- `GET /` — server-rendered identity front (Phlex view + generated RubyUI
  badge/card components; local CSS only). Shows organization name, canonical
  issuer, support contact, and an honest lab-scope notice. No authentication.
- `GET /.well-known/oma-enrollment` — public metadata per plan §11.4:
  protocol name/versions (`oma-enrollment`, `["0"]`), canonical issuer,
  organization display info, `enrollment_methods: []`. Advertises only what
  the server actually serves (the Doorkeeper/device-grant combination is
  proven in `tests/interop` only; wiring it in is P2). Fails closed with
  503 `{"error":"organization not configured"}` when unseeded. No secrets,
  no executable content.

## Tests run (2026-09-07, local)

`mise run server:test` → **6 runs, 29 assertions, 0 failures, 0 errors,
0 skips** (3 model validation tests + 3 integration tests: front render with
scope notice, metadata JSON contract, unseeded fail-closed).

## LAN hookup verification (executed)

- `mise run server:up` binds `0.0.0.0:3000` (HTTP, development only — real
  enrollment requires HTTPS per plan §6.2; no HTTP-fallback claim).
- From this machine via its LAN address (`http://192.168.1.10:3000`):
  `/` → 200 with organization render, `/.well-known/oma-enrollment` → 200
  with the metadata JSON (issuer `http://192.168.1.10:3000`), `/up` → 200.
- Burnt-ISO consumer test (live Omarchy environment, P0 stand-in layer):
  open `http://192.168.1.10:3000/` in the live desktop browser and
  `curl http://192.168.1.10:3000/.well-known/oma-enrollment` from a live
  terminal.

  **Booted-hardware result (2026-09-07, owner-executed):** the live PAM
  smoke (`zsh /opt/oma-id/run-smoke.sh`) passed all green on the burnt
  machine — the final consumer-path gap for the stand-in is closed with
  booted-hardware evidence (owner-reported; full transcript not retained).

## Installer work/school selector (stand-in slice, 2026-09-07)

`tests/iso-smoke/installer-choice.sh` (oma-id `a38d536`) is the plan §6.1
ownership choice for the ISO configurator, gated on the layer's presence so
personal builds are untouched (ADR-006). Personal use contacts no server;
School / work validates the OMA-ID server against the §11.4 metadata
contract and displays the organization confirmation with the requested
origin next to the canonical issuer. P0 boundary: no enrollment protocol
exists yet, so the work/school path ends in an explicit user choice —
continue as personal or abort — never a silent fallback (§6.4). The
validated choice is recorded to `/run/oma-id/standin-choice.json` (live
environment only).

Local verification (disposable Arch container): `validate` against the
real running Rails server → exit 0 with the confirmation table (requested
origin `http://host.docker.internal:3000` shown against canonical issuer
`http://192.168.1.10:3000` — the §6.2 comparison, live); wrong-protocol
metadata, truncated JSON, unreachable server, and invalid origin all
rejected with nonzero exits. CI contract tests run in omarchy-iso
`packaging-smoke` on every push.

## Boundaries and remaining work

- No authentication, sessions, people, or roles on this server yet (P1).
- No OIDC discovery/token issuance on this server yet (P2; evidence stays in
  `tests/interop`).
- RubyUI component styling is inert without the Tailwind/JS asset pipeline —
  the "RubyUI asset/accessibility checks pending" baseline item is NOT
  resolved by this slice; components render server-side only.
- The ISO-side fake agent does not talk to this server; the hookup test
  exercises reachability and trusted-metadata display, not the enrollment
  protocol (that requires P2 contracts).
- Failures hit while building this slice (all fixed): generator default
  `stale_when_importmap_changes` without the importmap gem; route with a
  leading-dot path needs an explicit `as:` for URL helpers; `ruby_ui` ships
  no eager component loading — components must be generated into the app
  (`rails g ruby_ui:component`); `rails new --skip-git` also skips
  `.gitignore` generation (tmp/log caches got committed once, amended away).
