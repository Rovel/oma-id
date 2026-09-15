# Porting the oma-id ISO layer to Omarchy quattro (v4)

Status: design (port plan). Upstream ref: omacom/omarchy-iso `quattro`
(basecamp/omarchy renamed master→quattro and restructured the installer).

## What quattro changed (relevant to us)

- **Layout**: `install/helpers/all.sh` is gone; the installer is phased
  (`install/{config,hardware,login,post-install,user,provisioning}/`), the
  runtime ships as packages (`omarchy`, `omarchy-settings`), and the live root
  mounts `/usr/share/omarchy` — not `/root/omarchy`.
- **Install**: a Python orchestrator (`omarchy-iso-install` +
  `usr/share/omarchy-iso/orchestrator/phases*.py`) replaces our
  `install_base_system`/`install_omarchy` shell functions. archinstall runs
  under it.
- **Deferred provisioning (upstream's own first-boot)**: `defer_provisioning`
  (Ctrl+C at the keyboard step or cidata) stages a provisioning state
  (`/var/lib/omarchy/provisioning/`), an initramfs LUKS keyfile for the
  provisioning window, and arms `omarchy-provision-owner.service` (first-boot
  owner setup). This overlaps our Option-1 first-boot bootstrap.
- **Configurator**: rewritten; sources a vendored `setup-form.sh` (shared with
  first-boot). The old `step/notice/clear_logo` helper vocabulary is gone.
- `.automated_script.sh` is a new script that runs the wizard + the
  orchestrator; our old hooks (`install_base_system`/`install_omarchy`
  functions) no longer exist.

## Integration points (Option-1 flow re-attached)

1. **STEP 0 / reservation** (unchanged conceptually): the new configurator is
   still the place with network + DMI + a human. Our keygen + reservation POST
   + possession proof attach as a gate at the top of the new configurator
   (school/work path), writing the device seed to `/run/oma-id/device.key` —
   unchanged.
2. **Target staging (§7.2 step 6)**: attach to the orchestrator, next to
   `stage_provisioning_state`: stage the agent/module/units/config/device.key
   into `/mnt` after archinstall mounts the target. The choice backup moves
   here too (durable, target-side).
3. **First boot**: our `oma-id-first-boot.service` stays the Option-1 flow
   (bootstrap retries → provisions the OMA account + local password → enables
   the daemon). Sequencing with quattro's `omarchy-provision-owner` (deferred
   first-boot owner setup) must be decided: on managed installs we provision
   the OMA person's account and the localadmin rescue stays for rescue only.
4. **LUKS**: quattro stages its own provisioning-window keyfile + auto-unlock;
   our separate disk-passphrase prompt may be unnecessary on quattro (the
   orchestrator generates + re-keys at first boot) — verify, then drop ours.
5. **Checkpoints + fail-fast + logs**: re-attach to the new flow (the live log
   contract changed: stdout is teed to the install log by .automated_script.sh).

## Plan of work

- Port 1: branch `oma-id-quattro` (done), build the unmodified quattro ISO and
  boot it on the Dell to see the new wizard/installer live (baseline).
- Port 2: STEP 0 re-attachment (choice + keygen + reservation) in the new
  configurator; choice persisted via the orchestrator's staging.
- Port 3: oma-id staging in the orchestrator's `stage_provisioning_state`
  phase (or immediately after it), + first-boot sequencing with
  omarchy-provision-owner.
- Port 4: end-to-end on hardware; evidence in docs/p0/.

## Status
- Branch created: oma-id-quattro (off upstream/quattro 4742669).
- Next: Port 1 (baseline build + boot).
