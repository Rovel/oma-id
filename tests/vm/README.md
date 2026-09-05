# Disposable login experiment

Status: procedure only; no VM run recorded yet. Containers cannot establish
SDDM, Quickshell lock, suspend/resume, encrypted boot, or recovery compatibility.

1. Select an Omarchy ISO and verify its checksum/signature using an independently
   trusted key. Record download URL, digest, source commits, package manifest,
   firmware settings, VM runner version, and virtual hardware in the evidence.
2. Create a disposable x86_64 UEFI VM with a new virtual disk, NAT networking, and
   a known recovery path. Do not pass host disks, PAM files, credentials, or devices.
3. Snapshot the clean guest. Build pinned `oma-id-agent` and `pam_oma_id` packages
   inside isolated Arch; record dependencies, build logs, licenses, installed
   paths, units, socket permissions, and upgrade/uninstall behavior.
4. Provision a fake local user and test TTY, then the real SDDM and Quickshell
   lock paths. Record exact prompts, identity mapping, IPC and PAM stages.
5. Repeat against the minimal Rails issuer with the same client scopes/claims.
   Record device-flow ID token, UserInfo, refresh and reauthentication outcomes.
6. Exercise disablement online/offline, lease expiry, sudo/polkit/SSH alternate
   paths, network loss, daemon failure, clock rollback, and snapshot restoration.
7. Demonstrate recovery from broken login configuration before declaring any
   change eligible for a managed workstation. Destroy disposable credentials.

Each result needs scenario ID, input/source pins, exact commands, expected and
actual behavior, sanitized logs, and pass/fail/blocked status. Never include
tokens, passwords, private keys, or disk recovery material in committed evidence.
Gate A remains unverified until E08/E09/E13 and recovery pass on the selected
stack; offline enforcement requires E10–E12/E17 separately.
