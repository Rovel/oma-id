#!/bin/bash
# OMA-ID P0 stand-in smoke test for the Omarchy ISO live environment.
# Mirrors tests/arch-pam/build.sh's scenario matrix, but against files at
# their installed ISO paths:
#   /usr/lib/security/pam_oma_id.so   (PAM module, standard search path)
#   /opt/oma-id/bin/fake_agent        (P0 test-harness agent)
#   /opt/oma-id/bin/pam-test-client   (C consumer harness)
# Runs as root in a disposable environment (live ISO or throwaway container).
# The mapped PAM service is omarchy-lock-password (Quickshell/Unlock), NOT
# sddm, so no real display-manager service file is touched. The module under
# test never reads the environment; only this harness does ($OMA_TEST_PASSWORD).
#
# NOTE: the Omarchy live airootfs ships zsh, not bash — this script must run
# under EITHER shell (build-iso.sh invokes it with an explicit interpreter).
# Stick to the shared bash/zsh subset: no arrays, no PIPESTATUS, no ${var,,}.
set -uo pipefail

MODULE=/usr/lib/security/pam_oma_id.so
AGENT=/opt/oma-id/bin/fake_agent
CLIENT=/opt/oma-id/bin/pam-test-client
SOCKET=/run/oma-id/agent.sock
MAPPED_SERVICE=omarchy-lock-password
UNMAPPED_SERVICE=oma-test-unmapped
AGENT_PASSWORD="p1nned-credential"

# Self-check the tools this script needs (clear diagnostics before any PAM
# activity, so a missing tool is not mistaken for a protocol failure).
for tool in awk date sleep mktemp; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool"; exit 1; }
done


results=/tmp/oma-id-smoke-results.tsv
: >"$results"
backup_dir=""

cleanup() {
  [[ -n "${agent_pid:-}" ]] && kill "$agent_pid" 2>/dev/null || true
  rm -f "/etc/pam.d/$MAPPED_SERVICE" "/etc/pam.d/$UNMAPPED_SERVICE"
  if [[ -n "$backup_dir" && -d "$backup_dir" ]]; then
    cp "$backup_dir/$MAPPED_SERVICE" "/etc/pam.d/$MAPPED_SERVICE"
    rm -rf "$backup_dir"
  fi
}
trap cleanup EXIT

for f in "$MODULE" "$AGENT" "$CLIENT"; do
  [[ -f "$f" ]] || { echo "missing: $f"; exit 1; }
done

mkdir -p /run/oma-id /etc/pam.d
# Back up any pre-existing mapped service file (installed systems only).
if [[ -f "/etc/pam.d/$MAPPED_SERVICE" ]]; then
  backup_dir=$(mktemp -d)
  cp "/etc/pam.d/$MAPPED_SERVICE" "$backup_dir/"
fi

printf 'auth\trequired\t%s\naccount\trequired\t%s\n' "$MODULE" "$MODULE" \
  >"/etc/pam.d/$MAPPED_SERVICE"
cp "/etc/pam.d/$MAPPED_SERVICE" "/etc/pam.d/$UNMAPPED_SERVICE"

now=$(date +%s)
wait_for_socket() {
  local deadline=$(( $(date +%s) + 10 ))
  while [ ! -S "$SOCKET" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 0.2; done
  [ -S "$SOCKET" ]
}
record() {
  # NB: do not name this variable "status" — read-only special in zsh.
  local name="$1" rc="$2"
  printf '%s\t%s\n' "$name" "$rc" >>"$results"
  if [ "$rc" -eq 0 ]; then echo "$name: ok"; else echo "$name: MISMATCH"; fi
}
scenario() {
  local name="$1" expected="$2" service="$3"; shift 3
  local output
  rm -f "$SOCKET"
  "$AGENT" --socket "$SOCKET" --subject person-1 --device device-1 \
    --ops "Login,Unlock" --trusted-time-floor $((now - 60)) \
    --min-revocation-epoch 1 "$@" >/dev/null 2>&1 &
  agent_pid=$!
  if wait_for_socket; then
    output=$(OMA_TEST_PASSWORD="${CLIENT_PASSWORD:-}" "$CLIENT" "$service" root)
  else
    output="agent-did-not-bind"
  fi
  kill "$agent_pid" 2>/dev/null || true
  wait "$agent_pid" 2>/dev/null || true
  echo "scenario-$name expected: $expected"
  echo "scenario-$name actual:   $output"
  if [ "$output" = "$expected" ]; then record "scenario-$name" 0; else record "scenario-$name" 1; fi
}

# Valid lease, mapped service, correct credential: both stages pass.
CLIENT_PASSWORD="$AGENT_PASSWORD"
scenario valid "auth:0 acct:0" "$MAPPED_SERVICE" \
  --not-before $((now - 60)) --expires-at $((now + 3600)) --revocation-epoch 1 \
  --password "$AGENT_PASSWORD"
# Wrong credential: PAM_AUTH_ERR (7) before the lease is consulted.
CLIENT_PASSWORD="not-the-credential"
scenario wrong "auth:7 acct:-1" "$MAPPED_SERVICE" \
  --not-before $((now - 60)) --expires-at $((now + 3600)) --revocation-epoch 1 \
  --password "$AGENT_PASSWORD"
# Expired lease with the CORRECT credential (plan §9.1): the exchange still
# passes, the authorization denies → PAM_AUTH_ERR (7).
CLIENT_PASSWORD="$AGENT_PASSWORD"
scenario expired "auth:7 acct:-1" "$MAPPED_SERVICE" \
  --not-before $((now - 7200)) --expires-at $((now - 3600)) --revocation-epoch 1 \
  --password "$AGENT_PASSWORD"
# Unmapped PAM service: fails closed (4) before prompting or contacting the agent.
CLIENT_PASSWORD="$AGENT_PASSWORD"
scenario unmapped "auth:4 acct:-1" "$UNMAPPED_SERVICE" \
  --not-before $((now - 60)) --expires-at $((now + 3600)) --revocation-epoch 1 \
  --password "$AGENT_PASSWORD"

# Mapped service but no agent at all: unavailable (4).
rm -f "$SOCKET"
output=$(OMA_TEST_PASSWORD="$AGENT_PASSWORD" "$CLIENT" "$MAPPED_SERVICE" root)
echo "scenario-down expected: auth:4 acct:-1"
echo "scenario-down actual:   $output"
if [ "$output" = "auth:4 acct:-1" ]; then record scenario-down 0; else record scenario-down 1; fi

echo "--- results ---"
cat "$results"
if awk '$2 != 0 { failed=1 } END {exit !failed}' "$results"; then
  echo "oma-id p0 smoke: FAILURES PRESENT"
  exit 1
fi
echo "oma-id p0 smoke: ALL GREEN"
