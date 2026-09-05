#!/bin/bash
# Runs only inside the disposable image. Never installs PAM/NSS on the host.
set -uo pipefail
pacman -Q > /out/packages.txt
go version > /out/go-version.txt 2>&1
rustc --version > /out/rust-version.txt
run_step() {
  local name="$1"
  shift
  "$@" >"/out/$name.log" 2>&1
  local status=$?
  printf '%s\t%s\n' "$name" "$status" >> /out/results.tsv
  printf '%s: exit %s\n' "$name" "$status"
}
run_step daemon go build -o /out/authd ./cmd/authd
run_step authctl go build -o /out/authctl ./cmd/authctl
run_step pam-generate go generate ./pam/
run_step pam-client go build -o /out/pam_authd ./pam
run_step nss cargo build --locked --release
run_step broker go -C authd-oidc-brokers build -o /out/authd-oidc ./cmd/authd-oidc
run_step broker-manager-tests env AUTHD_SKIP_ROOT_TESTS=1 go test ./internal/brokers/...
run_step generic-provider-tests go -C authd-oidc-brokers test ./internal/providers/...
python - <<'PY'
import json, pathlib
rows = [line.split('\t') for line in pathlib.Path('/out/results.tsv').read_text().splitlines()]
pathlib.Path('/out/results.json').write_text(json.dumps({name: int(code) for name, code in rows}, indent=2)+'\n')
PY
if awk '$2 != 0 { failed=1 } END {exit !failed}' /out/results.tsv; then exit 1; fi
