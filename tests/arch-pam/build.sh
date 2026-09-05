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
run_step build-module cargo build --locked --release -p oma-id-pam-module
if [ -f target/release/libpam_oma_id.so ]; then
  cp target/release/libpam_oma_id.so /out/pam_oma_id.so
fi
if awk '$2 != 0 { failed=1 } END {exit !failed}' /out/results.tsv; then exit 1; fi
