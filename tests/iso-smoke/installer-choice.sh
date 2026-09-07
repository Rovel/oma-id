#!/bin/bash
# OMA-ID P0 stand-in installer selector for the Omarchy ISO configurator.
# Plan §6.1/§6.2/§6.4, wired per §11.4 metadata:
#   - "How will this computer be used?" Personal use (default) / School / work.
#   - Personal: no server contact, the normal install continues untouched.
#   - School / work: ask for the OMA-ID server URL, fetch the public
#     enrollment metadata, and display the organization confirmation
#     (name, canonical issuer, support contact, requested origin — the user
#     compares what they typed against what the server claims).
#   - P0 lab slice: no enrollment protocol exists yet (P2). A work/school
#     choice must NEVER silently fall back to personal (§6.4): the user
#     explicitly chooses to continue as personal or aborts.
# Runs under the live root's bash via the configurator, but stays in the
# bash/zsh-shared subset (no arrays, no PIPESTATUS, no variable named
# "status" — it is read-only in zsh).
set -uo pipefail

METADATA_PATH="/.well-known/oma-enrollment"
CHOICE_DIR="/run/oma-id"
CHOICE_FILE="$CHOICE_DIR/standin-choice.json"

abort_choice() {
  echo "oma-id: ${1:-aborted}"
  echo "Nothing was enrolled and no settings were changed."
  exit 1
}

# validate <url> — headless path (CI-testable): fetch the metadata, check the
# contract, print the confirmation table. Exit 0 only on a valid response.
validate() {
  local url="${1%/}"
  local body rc

  if [[ ! "$url" =~ ^https?://[^/[:space:]]+$ ]]; then
    echo "oma-id: '$url' is not a valid origin (expected like https://id.example.org)" >&2
    return 1
  fi

  body=$(curl -fsS --max-time 10 "$url$METADATA_PATH" 2>&1)
  rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "oma-id: could not fetch $url$METADATA_PATH (network or server error)" >&2
    echo "$body" >&2
    return 1
  fi

  if ! printf '%s' "$body" | jq -e '
      .protocol.name == "oma-enrollment" and
      (.protocol.versions | type == "array") and
      (.issuer | type == "string" and startswith("http")) and
      (.organization.name | type == "string") and
      (.organization.support_email | type == "string") and
      (.enrollment_methods | type == "array")
    ' >/dev/null 2>&1; then
    echo "oma-id: server responded, but the enrollment metadata does not match the oma-enrollment contract" >&2
    return 1
  fi

  echo "---- organization confirmation ----"
  echo "Requested origin:  $url"
  echo "Canonical issuer:  $(printf '%s' "$body" | jq -r '.issuer')"
  echo "Organization:      $(printf '%s' "$body" | jq -r '.organization.name')"
  echo "Support contact:   $(printf '%s' "$body" | jq -r '.organization.support_email')"
  echo "Enrollment methods: $(printf '%s' "$body" | jq -c '.enrollment_methods')"
  echo "----------------------------------"
  echo "Compare the requested origin with the canonical issuer before trusting this server."
}

save_choice() {
  local mode="$1" server="$2" note="$3"
  mkdir -p "$CHOICE_DIR"
  jq -n --arg mode "$mode" --arg server "$server" --arg note "$note" \
    '{mode: $mode, server: $server, note: $note}' >"$CHOICE_FILE"
  echo "oma-id: recorded $CHOICE_FILE (live environment only; not installed to disk)"
}

interactive() {
  local mode url
  mode=$(printf 'Personal use\nSchool / work\n' |
    gum choose --header "How will this computer be used?") || abort_choice

  if [[ "$mode" == "Personal use" ]]; then
    save_choice "personal" "" "personal install selected; no OMA-ID server contact"
    echo "oma-id: personal install — continuing the standard setup."
    return 0
  fi

  # School / work: identify the OMA-ID server (§6.2).
  while true; do
    url=$(gum input --placeholder "https://id.example.org" --prompt "OMA-ID server> ") || abort_choice
    if validate "$url"; then
      break
    fi
    echo "oma-id: retry, or Ctrl+C to abort"
    echo
  done

  # Honest P0 boundary: validation is all this slice can do. Never a silent
  # personal fallback (§6.4) — the user decides explicitly.
  echo
  echo "oma-id: this P0 slice has validated the server connection only."
  echo "oma-id: enrollment activation arrives with the Phase-2 protocol; nothing is enrolled yet."
  echo
  if gum confirm "Continue with a PERSONAL install for now?"; then
    save_choice "work-school" "$url" "validated; enrollment activation pending P2; personal install continued by explicit user choice"
    echo "oma-id: continuing the standard setup (personal)."
    return 0
  fi
  abort_choice "work/school selected but enrollment activation is not available on this image."
}

case "${1:-}" in
  validate)
    [[ -n "${2:-}" ]] || { echo "usage: $0 validate <server-url>" >&2; exit 2; }
    validate "$2"
    ;;
  "")
    interactive
    ;;
  *)
    echo "usage: $0 [validate <server-url>]" >&2
    exit 2
    ;;
esac