#!/bin/bash
# Runs only inside the disposable Arch image. Never installs PAM/NSS on the host.
set -uo pipefail
mkdir -p /out
rustc --version > /out/rust-version.txt 2>&1 || true
run_step() {
  local name="$1"
  shift
  "$@" >"/out/$name.log" 2>&1
  local status=$?
  printf '%s\t%s\n' "$name" "$status" >> /out/results.tsv
  printf '%s: exit %s\n' "$name" "$status"
}

run_step cargo-test cargo test --locked
run_step build-module cargo build --locked --release -p oma-id-pam-module -p oma-id-agent-daemon
if [ -f target/release/libpam_oma_id.so ]; then
  cp target/release/libpam_oma_id.so /out/pam_oma_id.so
fi

# --- Real libpam consumer scenarios (fake agent only; no production daemon) ---
MODULE=/out/pam_oma_id.so
AGENT=target/release/fake_agent
SOCKET=/run/oma-id/agent.sock
mkdir -p /etc/pam.d /run/oma-id
printf 'auth\trequired\t%s\naccount\trequired\t%s\n' "$MODULE" "$MODULE" > /etc/pam.d/oma-test
cp /etc/pam.d/oma-test /etc/pam.d/oma-unmapped

run_step compile-client gcc -O2 -Wall -o /out/pam-test-client /src/pam-test-client.c -lpam

now=$(date +%s)
wait_for_socket() {
  local deadline=$(( $(date +%s) + 10 ))
  while [ ! -S "$SOCKET" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 0.2; done
  [ -S "$SOCKET" ]
}
# scenario <name> <expected-output> <service> -- start the agent with the
# given lease, run the PAM client for <service>, and compare the codes.
scenario() {
  local name="$1" expected="$2" service="$3"; shift 3
  local agent_pid="" output
  rm -f "$SOCKET"
  "$AGENT" --socket "$SOCKET" --subject person-1 --device device-1 \
    --ops "Login,Unlock" --trusted-time-floor $((now - 60)) \
    --min-revocation-epoch 1 "$@" &
  agent_pid=$!
  if wait_for_socket; then
    output=$(/out/pam-test-client "$service" root)
  else
    output="agent-did-not-bind"
  fi
  kill "$agent_pid" 2>/dev/null || true
  {
    echo "expected: $expected"
    echo "actual:   $output"
  } > "/out/scenario-$name.log"
  if [ "$output" = "$expected" ]; then
    printf 'scenario-%s\t0\n' "$name" >> /out/results.tsv
    echo "scenario-$name: ok"
  else
    printf 'scenario-%s\t1\n' "$name" >> /out/results.tsv
    echo "scenario-$name: MISMATCH (see /out/scenario-$name.log)"
  fi
}

# Valid lease, mapped service: auth and account stages both pass.
scenario valid "auth:0 acct:0" oma-test \
  --not-before $((now - 60)) --expires-at $((now + 3600)) --revocation-epoch 1
# Expired lease: explicit denial from the agent (PAM_AUTH_ERR = 7).
scenario expired "auth:7 acct:-1" oma-test \
  --not-before $((now - 7200)) --expires-at $((now - 3600)) --revocation-epoch 1
# Mapped service but no agent at all: unavailable (PAM_SYSTEM_ERR = 4).
rm -f "$SOCKET"
output=$(/out/pam-test-client oma-test root)
{
  echo "expected: auth:4 acct:-1"
  echo "actual:   $output"
} > /out/scenario-down.log
if [ "$output" = "auth:4 acct:-1" ]; then
  printf 'scenario-down\t0\n' >> /out/results.tsv
  echo "scenario-down: ok"
else
  printf 'scenario-down\t1\n' >> /out/results.tsv
  echo "scenario-down: MISMATCH (see /out/scenario-down.log)"
fi
# Unmapped PAM service: the module fails closed (PAM_SYSTEM_ERR = 4).
scenario unmapped "auth:4 acct:-1" oma-unmapped \
  --not-before $((now - 60)) --expires-at $((now + 3600)) --revocation-epoch 1

if awk '$2 != 0 { failed=1 } END {exit !failed}' /out/results.tsv; then exit 1; fi
