# P3-a: admin-approved device enrollment (plan §7.2, unattended mode)

Status: **implemented and live-verified** (oma-id `18acf18`, omarchy-iso pin
`5931766`+). Replaces the manual `oma_id:register_device` key-extraction
step for the ISO flow: the device asks, the administrator accepts in the
browser, everything else is automatic. The rake task remains as the
technician pre-provisioning path (§6.3) and now shares the same
`OmaId::EnrollDevice` service.

## Transaction shape (plan §7.2 subset)

This slice implements the unattended/admin-approval mode:

1. **Request created by the device** (§7.2 step 1): the agent POSTs
   `public_key_hex`, proposed `requested_device_id`, and hardware identity
   (DMI `sys_vendor`/`product_name`/`product_serial`, `/etc/machine-id`
   fallback) to `POST /api/v1/enrollment-requests`. Unauthenticated first
   contact; flood-limited per IP; grants **no** organizational access (§7.3
   `pending`). Idempotent per key — a re-post refreshes details, never
   duplicates (§7.2 "retries must not create duplicate devices").
2. **Administrator reviews in the trusted browser** (§7.2 step 2, the
   admin-approval path of §6.3): `/enrollment_requests` (owner or
   identity_admin) shows device name, manufacturer/model, serial, machine
   id, key prefix, requested id, and the **key-possession status**.
3. **Key possession proof** (§7.2 step 4, minimal form): the agent polls
   `GET /api/v1/enrollment-requests/:id` with a device signature over
   `enrollment-status|<id>|<timestamp>` (±300s replay window, same shape as
   check-ins). A verified poll stamps `key_possession_verified_at` once;
   **acceptance is refused without it** (`EnrollmentRequest::NotReady`).
4. **Acceptance bound to the transaction** (§7.2 step 4 binding): admin
   action → `Device` created `active` for the chosen `Person` +
   `PosixIdentityMapping` allocated (§8.4) — all in one DB transaction with
   audit events (`enrollment.request`, `enrollment.accept`, `enrollment.reject`,
   `enrollment.clear`). The response to the agent's poll carries the
   server-assigned `device_id`.
5. **Agent adoption**: the assigned id is persisted (0600) in
   `<state_dir>/enrollment.json`; check-ins proceed with it. Rejection is
   terminal for that key (§7.3); the admin can clear the request so the
   device posts a fresh one (new lifecycle).

## Security properties (tested)

- Unknown device / bad signature / stale timestamp / unknown request id:
  opaque 401, no oracle.
- Unauthenticated surface is exactly one endpoint (the request POST),
  flood-limited; everything after is signature- or role-gated.
- Acceptance refuses without possession proof; re-acceptance of a resolved
  request refuses; `EnrollDevice` refuses re-binding an existing device to
  a different person/key.
- Agent fail-closed: unreachable server → non-zero exit, no socket (CI
  smoke unchanged); rejection → terminal error, nothing recorded.

## Live verification (2026-09-09, dev machine)

1. Fresh agent (tmpfs-like state dir, WSL, no DMI): `device not enrolled —
   requesting enrollment (Device (machine-id 3846…))` → `enrollment request
   1 pending — waiting for administrator approval`.
2. Signed poll stamped `key_possession_verified_at` server-side
   (`possession=true` observed by the admin before acceptance).
3. Admin accept (`enroll-demo-1`, owner) → device `active`, POSIX mapping
   `owner` uid=10000 allocated, audit recorded.
4. Agent: `enrollment accepted — device id 'enroll-demo-1' assigned` →
   `check-in ok (hwm=1, leases=1)`.
5. Local provisioning attempted → `groupadd` permission denied under the
   unprivileged demo agent → **fail closed, no socket** (expected; the
   systemd agent runs as root, and the §8.1/§8.4 provisioning chain is
   container-verified from the earlier slice).

## Live verification (2026-09-11, real hardware)

Live ISO `omarchy-2026.09.10-x86_64.iso` (locally built, pin `18acf18`)
booted on a physical laptop; only the server URL was written to
`/etc/oma-id-agent.json`. The self-enrollment flow then ran without any
manual key extraction:

1. **Request posted by the machine itself** (02:53): real DMI identity
   (manufacturer, model, serial number, machine-id — hardware-specific
   values deliberately scrubbed from this public repo), requested id
   `workstation-1` — the review UI showed the full hardware identity the
   administrator judged.
2. **Possession stamped by the signed poll** at 02:53:19 (the review UI
   showed `key possession VERIFIED` before the administrator acted).
3. **Accepted in the browser review UI** at 03:09:29 (actor
   `admin:owner@oma-id.invalid` — the P1-a session path, role-gated):
   device `workstation-1` bound to the owner, `active`, POSIX mapping
   `owner` uid=10000 home=/home/owner.
4. **Agent adopted the assigned id within seconds**: `enrollment accepted —
   device id 'workstation-1' assigned` → `check-in ok` → leases epochs 31
   and 32 issued and verified; server-side audit `enrollment.request` /
   `enrollment.accept` both success.
5. Server-side evidence: `Device.find_by(device_id: "workstation-1")`
   carries exactly the accepted key; `last_check_in_at` 03:09:37.

Note: on the live ISO the device key + enrollment record are tmpfs, so a
live reboot posts a fresh request (new key → the old accepted request stays
accepted but inert; each new key gets its own §7.3 lifecycle). The installed
system is the persistent target.

Remaining for the full consumer path on this machine: set the local
password (`chpasswd`) and exercise PAM (pam-test-client, then the wired
SDDM/lock screens).

## Suites

- Rails: 53 runs / 198 assertions / 0 failures (new: enrollment-request API,
  model lifecycle, admin-review integration incl. role gating).
- Rust: full workspace green via `mise run p0:agent-core`, incl. 4 new
  enrollment tests (mock-issuer flow, signed-poll verification, rejection
  terminality, unreachable-server cleanliness, 0600 record persistence).

## Boundary (do not overclaim)

- The §7.2 OAuth/trusted-browser *user*-driven mode (steps 1–2 with user
  authentication) is NOT this slice — this is the admin-approval variant.
- §7.4 mTLS/device-CA credentials, server challenges (the signed poll is the
  possession proof), installation reservation, and activation evidence are
  later work. The lease endpoint still uses the bearer stand-in.
- Live ISO tmpfs: `/var/lib/oma-id` (device key + enrollment record) is lost
  on reboot of a live session; each boot of a live ISO re-enrolls. The
  installed system (P4) is the persistent target.
