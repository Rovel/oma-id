#!/bin/bash
# OMA-ID P0 stand-in installer selector for the Omarchy ISO configurator.
# Plan §6.1/§6.2/§6.4, wired per §11.4 metadata:
#   - "How will this computer be used?" Personal use (default) / School / work.
#   - Personal: no server contact, the normal install continues untouched.
#   - School / work: ensure network (ethernet is automatic; Wi-Fi via iwctl),
#     ask for the OMA-ID server URL, fetch the public enrollment metadata,
#     and display the organization confirmation (name, canonical issuer,
#     support contact, requested origin — the user compares what they typed
#     against what the server claims).
#   - P0 lab slice: no enrollment protocol exists yet (P2). A work/school
#     choice must NEVER silently fall back to personal (§6.4): the user
#     explicitly chooses to continue as personal or aborts.
# Visual language matches the other configurator steps: the Omarchy logo via
# gum (clear_logo replica) with the same padding and colors.
# Runs under the live root's bash via the configurator, but stays in the
# bash/zsh-shared subset (no arrays, no PIPESTATUS, no variable named
# "status" — it is read-only in zsh).
set -uo pipefail

METADATA_PATH="/.well-known/oma-enrollment"
CHOICE_DIR="/run/oma-id"
CHOICE_FILE="$CHOICE_DIR/standin-choice.json"
OMA_LOGO="${OMARCHY_PATH:-/root/omarchy}/logo.txt"

# --- visual language (oma_-namespaced; NEVER shadow the upstream
# configurator's step/clear_logo/oma_say — this script runs inside the same
# shell, and redefining those names used to replace the Omarchy
# presentation for every configurator oma_step after ours, which is what the
# burnt-machine session showed: keyboard/user/timezone losing the theme).
# Inside the configurator the REAL upstream clear_logo and PADDING_LEFT are
# already in scope (helpers/all.sh is sourced before we run); use them. The
# oma_ replicas exist only for the standalone CI smoke run.
oma_padding() {
  OMA_PADDING=${PADDING_LEFT:-$((($(tput cols 2>/dev/null || echo 80) - 20) / 2))}
  [[ $OMA_PADDING -lt 0 ]] && OMA_PADDING=0
}

oma_clear_logo() {
  if declare -F clear_logo >/dev/null; then
    clear_logo  # the real upstream helper: logo.txt + its own padding
    return
  fi
  # Standalone (CI/headless): plain OMA-ID header, upstream-like padding.
  oma_padding
  printf "\033[H\033[2J"
  if [[ -f "$OMA_LOGO" ]]; then
    gum style --foreground 2 --padding "1 0 0 $OMA_PADDING" "$(<"$OMA_LOGO")"
  else
    gum style --foreground 2 --padding "1 0 0 $OMA_PADDING" "OMA-ID"
  fi
}

oma_step() {
  oma_clear_logo
  echo
  oma_padding
  gum style --padding "0 0 0 $OMA_PADDING" "$1"
  echo
}

oma_say() {
  oma_padding
  gum style --padding "0 0 0 $OMA_PADDING" "$@"
}

oma_abort_choice() {
  oma_step "oma-id: ${1:-aborted}"
  oma_say "Nothing was enrolled and no settings were changed."
  oma_say "You can retry later by restarting the installer."
  exit 1
}

# --- connectivity ---
have_route() {
  ip route show default 2>/dev/null | grep -q default
}

# oma_ensure_network — live-only path: the work/school flow needs connectivity.
# Ethernet is configured automatically on the live ISO when a cable is
# connected; Wi-Fi goes through iwctl (iwd ships on the ISO).
oma_ensure_network() {
  if have_route; then
    return 0
  fi
  oma_step "Network connection needed"
  oma_say "Reaching the OMA-ID server requires a network connection."
  oma_say "Ethernet is configured automatically when a cable is connected."
  oma_say "For Wi-Fi, connect with iwctl, then quit it (Ctrl+D) to continue."
  echo
  while true; do
    action=$(printf 'Wi-Fi (iwctl)\nRetry detection\n' |
      gum choose --header "Set up the network") || oma_abort_choice "network setup cancelled"
    if [[ "$action" == "Wi-Fi (iwctl)" ]]; then
      oma_clear_logo
      iwctl
    fi
    if have_route; then
      oma_step "Network connected"
      return 0
    fi
    oma_say "No default route yet."
    echo
  done
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
  local mode="$1" server="$2" note="$3" device="${4:-}"
  mkdir -p "$CHOICE_DIR"
  jq -n --arg mode "$mode" --arg server "$server" --arg note "$note" --arg device "$device" \
    '{mode: $mode, server: $server, note: $note, device: $device}' >"$CHOICE_FILE"
  oma_say "Recorded $CHOICE_FILE (live environment; consumed by the target provisioning step)."
}

interactive() {
  local mode url
  oma_step "Let's set up your machine..."
  mode=$(printf 'Personal use\nSchool / work\n' |
    gum choose --header "How will this computer be used?") || oma_abort_choice

  if [[ "$mode" == "Personal use" ]]; then
    save_choice "personal" "" "personal install selected; no OMA-ID server contact"
    oma_say "Personal install — continuing the standard setup."
    return 0
  fi

  # School / work: identify the OMA-ID server (§6.2).
  oma_ensure_network
  oma_step "Connect to your organization"
  oma_say "Enter the OMA-ID server address exactly as given by your organization."
  echo
  while true; do
    url=$(gum input --placeholder "https://id.example.org" --prompt "OMA-ID server> ") || oma_abort_choice
    if validate "$url"; then
      break
    fi
    oma_say "Could not validate that server. Retry, or Ctrl+C to abort."
    echo
  done

  # Name the machine (§7.2 step 1 device details): becomes the installed
  # system's hostname AND the enrollment proposal — set once, here.
  oma_step "Name this machine"
  oma_say "Used as the hostname of the installed system and proposed as its"
  oma_say "device id at enrollment (the administrator can still rename it)."
  echo
  while true; do
    machine=$(gum input --placeholder "workstation-1" --value "${OMA_ID_DEVICE:-workstation-1}" \
      --prompt "Machine name> ") || oma_abort_choice
    machine=$(printf '%s' "$machine" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
    if printf '%s' "$machine" | grep -qE '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'; then
      break
    fi
    oma_say "Use letters, digits, and dashes (no leading or trailing dash)."
  done

  # P3-a: the installed system self-enrolls on first boot — the agent posts
  # its key + hardware identity and an administrator accepts it in the
  # server's review UI. The user decides explicitly (§6.4): enroll the
  # managed install, or continue as personal. Never silent.
  echo
  if gum confirm --padding "0 0 0 $OMA_PADDING" "Set up OMA-ID management on the installed system?"; then
    save_choice "work-school" "$url" "installed system will self-enroll on first boot; admin acceptance required" "$machine"
    oma_say "The installed system (hostname: $machine) will enroll on first boot."
    oma_say "An administrator must accept the device in the server's enrollment review."
    return 0
  fi
  save_choice "work-school-personal" "$url" "server validated; user chose to continue as personal (§6.4 explicit)" "$machine"
  oma_say "Continuing as a personal install — no OMA-ID management will be installed."
}

case "${1:-}" in
  validate)
    [[ -n "${2:-}" ]] || { echo "usage: $0 validate <server-url>" >&2; exit 2; }
    validate "$2"
    ;;
  check-network)
    # CI-testable connectivity probe: exit 0 when a default route exists.
    have_route
    ;;
  "")
    interactive
    ;;
  *)
    echo "usage: $0 [validate <server-url>] [check-network]" >&2
    exit 2
    ;;
esac