# Installer-performed enrollment — Option 1 spec (P3-a revision)

Status: **design** (not yet implemented). Supersedes the first-boot self-enrollment
as the target flow. Plan contract: oma-id_plan.md §6.3, §7.2, §10, §16.

## Why this replaces the current flow

The current flow defers identity work to first boot — an environment with no
network guarantee, no interactivity, and no logs we can read after a reboot.
Live-boot evidence (this series) showed the fragility: the enrollment choice in
`/run` (tmpfs) could vanish before the provision hook ran; the agent could not
self-enroll without first-boot network; the admin had to discover a request that
only appeared after the install; and login dead-ended until enrollment +
provisioning + password happened in sequence.

The installer already has network (STEP 0), real hardware identity (DMI), and a
human present. That is where the enrollment belongs.

## Trust boundaries (unchanged, re-affirmed)

- Device key-pair: generated in the live installer in RAM; staged **only** into the
  LUKS-encrypted target; never in the ISO/image baseline (§7.2 step 6).
- Disk (LUKS) passphrase: created by the installer, displayed once, existing only
  in the live RAM; **never sent to the server** (§10/§242/§397). The server's
  influence is policy only (the request carries `disk: encrypted` as a proof, not
  the secret).
- Person long-term password: set locally on the machine, never synced (§10). The
  server issues a **one-time bootstrap credential** consumed by the agent at first
  provisioning; the user rotates at first login.
- Server never holds the device private key or the disk passphrase.

## End-to-end sequence

### Phase A — Installer (live environment)
1. STEP 0 (existing): personal/school + network + server-URL validation + machine
   name. Write an install *intent* (still `/run`, but now only transient — see
   commit step 6).
2. Generate the device ed25519 key-pair in the live RAM.
3. POST an enrollment request to the server: device public key, hardware identity
   (DMI manufacture/model/serial/machine-id), machine name, `disk: encrypted`
   policy proof. Server returns an enrollment id (pending) + nonce.
4. The review UI shows a **pending reservation** (before the disk is even
   formatted): machine name, identity, `disk: encrypted`, requested device id.
   The admin can accept while the install continues (§7.2 step 2) — late
   acceptance is fine (first boot waits and retries).
5. Install proceeds: partition + LUKS (installer-generated passphrase, shown once
   at the end) + base system (existing omarchy flow).
6. Once `/mnt` exists, **stage directly into the encrypted target** (replaces the
   `/run`-only handoff — this is the commit step; the target disk is the durable
   source of truth):
   - `/etc/oma-id-agent.json` — server_url, device_id, state_dir, socket_path
   - `/usr/bin/oma-id-agent`, `/usr/lib/security/pam_oma_id.so`, the systemd unit
     (enabled)
   - `/var/lib/oma-id/device.key` — the generated private key (0600, inside LUKS)
   - `/etc/oma-id/enrollment.json` — enrollment id, nonce, `state: reserved`
   - `/etc/oma-id/standin-choice.json` — the server/name values (durable backup,
     already landed)
   - `/etc/pam.d/{sddm,omarchy-lock-*}` — §8.2 wiring
   - outcome + cmd timestamp to `/var/log/oma-id-provision-install.log` (persistent)
7. On the installed target, remove nothing; the first-boot service consumes this
   staged state.

### Phase B — First boot (installed system)
1. A **systemd oneshot** `oma-id-first-boot.service`
   (`After=network-online`, bounded) runs `oma-id-first-boot.sh`:
   - idempotent via a flag file (`/var/lib/oma-id/state: staged → activated`)
   - load staged key + enrollment id; wait for network with bounded Retry+backoff
   - signed check-in (existing protocol). If the device is still `pending`, the
     response is `pending`; the bootstrapper waits and retries (no dead-end, late
     acceptance handled).
2. On acceptance + first signed check-in, the server flips the device
   `pending → active` and returns: leases, POSIX mapping, and the **one-time
   bootstrap credential** for the provisioned person.
3. The bootstrapper provisions the local account (useradd per §8.4 mapping) and
   applies the bootstrap credential via local `chpasswd`; marks `activated`;
   posts the **activation evidence ack** to the server (§7.2 step 8); starts the
   regular daemon.
4. SDDM lists the provisioned account; login with the bootstrap credential; forced
   rotation to a locally-set password (bootstrap is single-use, discarded).

### Phase C — Server (Rails)
- `EnrollmentRequest` (existing) reused. Acceptance binds the device to the person
  (existing `EnrollDevice`) and records the reservation.
- **New**: device `state: pending` on acceptance; the first signed check-in (signed
  proof the installed machine holds the key) flips it to `active`. This is the
  reserve-then-activate step (§6.3/§7.2 step 5).
- **New**: one-time bootstrap credential — generated at acceptance, stored only as
  a hash/token-reference, delivered in the first `active` check-in response, marked
  consumed, never logged, filtered from params (Rails strong-params filter).
- **New**: `POST /api/v1/device/first-boot-ack` — baseline evidence ack recorded to
  audit (§7.2 step 8).
- Review UI: show `disk: encrypted` from the request and a "reservation" badge.

## Components to build
- **Rails**: accept→pending device; bootstrap credential (single-use) delivered in
  first check-in; pending→active flip; first-boot ack endpoint; UI additions.
- **Agent (Rust)**: bootstrap mode (`oma-id-agent bootstrap` or staged script):
  first check-in consuming the bootstrap credential + activation flag, then hand
  off to the daemon. Reuse existing check_in/apply_check_in/provisioning.
- **ISO layer**: installer generates key + posts request (installer-choice +
  staging); create-missing-PAM retained; `oma-id-first-boot.service` + script;
  loud verdicts + persistent per-stage logs retained.

## Improvements folded in (from this series)
- No `/run`-only coupling: the commit step writes everything the installed system
  needs into the LUKS target; `/run` holds only transient install intent.
- No first-boot discovery dependency: the key + request exist before first boot;
  first boot only proves and consumes (§7.2 reserve-then-activate).
- No admin-hunting for a request: the server sees the reservation before the disk
  is formatted.
- Login works at first boot (bootstrap credential); disk passphrase and the login
  credential are distinct secrets (no reuse confusion). Plan §10 separate-trust.
- Bounded retry/backoff + persistent state + loud verdicts + on-disk logs; late
  acceptance never dead-ends.
- Auth/identity/lease/revocation/HWM machinery (lease-v1 signing, key sets,
  opaque denials, §5.3, §9.2 aging) untouched.

## Out of scope (recorded, not dropped)
- TPM2 / FIDO2 disk enrollment — requires the Omarchy boot path verified on
  hardware (§10 [S29]); future slice.
- Recovery-key escrow (§10) — separate mechanism, separate slice.
- Passkeys / P1-b (owner-deferred).

## Success criteria
- A school/work install reaches a SDDM login at first boot with a provisioned
  account, using the bootstrap credential then a rotated local password.
- The server sees the reservation before/while the disk formats; no `choice mode
  none`, no silent unmanaged system, no tmpfs-dependent staging (persistent logs
  on the installed disk).
- Plan constraints hold: disk passphrase never transits the server; device key
  never in the ISO; person password set locally.
