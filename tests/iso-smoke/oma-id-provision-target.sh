#!/bin/bash
# Provision OMA-ID management into a TARGET system root (plan §7.2 step 6:
# "install the trusted packages and stage only the minimal key-bound
# activation state"). Runs in the live install environment AFTER the omarchy
# install has written its own /etc/pam.d, so our wiring is never overwritten.
#
# Usage: oma-id-provision-target.sh <target-root> [server-url] [device-id]
# Gated: the installer choice file must say work-school (ADR-006); personal
# and work-school-personal installs get NOTHING.
#
# What is staged:
#   <root>/usr/bin/oma-id-agent          the pinned agent binary (from the ISO)
#   <root>/usr/lib/security/pam_oma_id.so
#   <root>/usr/lib/systemd/system/oma-id-agent.service  (enabled)
#   <root>/etc/oma-id-agent.json         the §6.2-validated server URL
#   <root>/etc/pam.d/{sddm,omarchy-lock-*} wired to pam_oma_id (§8.2)
#
# The device key is NOT staged (§7.2 step 6: never into a reusable image
# baseline) — the agent generates it on first boot of the installed system
# and self-enrolls; an administrator accepts the request in the review UI.
set -euo pipefail

root="${1:?usage: oma-id-provision-target.sh <target-root> [server-url] [device-id]}"
server_url="${2:-}"
device_id="${3:-workstation-1}"
choice_file=/run/oma-id/standin-choice.json

# --- gate (§6.4 / ADR-006): only an explicit work-school choice provisions ---
if [[ -f "$choice_file" ]]; then
  mode=$(jq -r '.mode // empty' "$choice_file")
else
  mode=""
fi
if [[ "$mode" != "work-school" ]]; then
  echo "oma-id-provision-target: choice mode '${mode:-none}' — no OMA-ID management staged (personal install)."
  exit 0
fi

# The server URL comes from the §6.2-validated choice unless given.
if [[ -z "$server_url" ]]; then
  server_url=$(jq -r '.server // empty' "$choice_file")
fi
if [[ -z "$server_url" ]]; then
  echo "oma-id-provision-target: no validated server URL in the choice file" >&2
  exit 1
fi

# The live environment already has the pinned artifacts at their system
# paths (installed by the ISO layer) — one source of truth.
agent_src=/usr/bin/oma-id-agent
module_src=/usr/lib/security/pam_oma_id.so
unit_src=/usr/lib/systemd/system/oma-id-agent.service
[[ -x "$agent_src" ]] || { echo "oma-id-provision-target: missing $agent_src" >&2; exit 1; }
[[ -f "$module_src" ]] || { echo "oma-id-provision-target: missing $module_src" >&2; exit 1; }
[[ -f "$unit_src" ]] || { echo "oma-id-provision-target: missing $unit_src" >&2; exit 1; }

install -D -m 0755 "$agent_src" "$root/usr/bin/oma-id-agent"
install -D -m 0644 "$module_src" "$root/usr/lib/security/pam_oma_id.so"
install -D -m 0644 "$unit_src" "$root/usr/lib/systemd/system/oma-id-agent.service"

# Config: the §6.2-validated server URL (device_id is the agent's PROPOSED
# id — the administrator sees and can rename it at acceptance). State lives
# in /var/lib/oma-id (persistent on the installed system).
install -d -m 0755 "$root/etc"
cat >"$root/etc/oma-id-agent.json" <<EOF
{
  "server_url": "$server_url",
  "device_id": "$device_id",
  "state_dir": "/var/lib/oma-id",
  "socket_path": "/run/oma-id/agent.sock",
  "check_in_interval_seconds": 300
}
EOF
chmod 0644 "$root/etc/oma-id-agent.json"

# Enable the unit (symlink, matching systemdctl is-enabled semantics).
install -d -m 0755 "$root/etc/systemd/system/multi-user.target.wants"
ln -sfn /usr/lib/systemd/system/oma-id-agent.service \
  "$root/etc/systemd/system/multi-user.target.wants/oma-id-agent.service"

# §8.2 PAM wiring: auth + account through pam_oma_id. The same wiring the
# live ISO layer applies, applied to the target AFTER the omarchy install.
for service in sddm omarchy-lock-password omarchy-lock-fingerprint; do
  pam="$root/etc/pam.d/$service"
  [[ -f "$pam" ]] || { echo "oma-id-provision-target: $pam missing (omarchy install incomplete?)" >&2; exit 1; }
  if ! grep -q "pam_oma_id.so" "$pam"; then
    printf '# OMA-ID managed login (added by oma-id-provision-target)\nauth        required    pam_oma_id.so\naccount     required    pam_oma_id.so\n' >>"$pam"
  fi
done

echo "oma-id-provision-target: staged agent+module+unit+config into $root (server: $server_url, proposed device: $device_id)"
echo "oma-id-provision-target: first boot will self-enroll; an administrator must accept the device."
