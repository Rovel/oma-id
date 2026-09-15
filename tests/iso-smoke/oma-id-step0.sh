#!/bin/bash
# OMA-ID STEP 0 (docs/p0/installer-enrollment.md, §6.3/§7.2 step 5) — quattro
# port. SOURCED by the ISO configurator after its helpers are defined, so the
# quattro step/say/abort vocabulary is reused (no shadowing: our functions are
# oma_-prefixed). On the managed path this generates the device key, POSTs the
# reservation (public key + DMI + disk_encryption: planned) and proves key
# possession, writing:
#   /run/oma-id/standin-choice.json  (mode/server/device)
#   /run/oma-id/device.key           (32-byte seed, 0600)
#   /run/oma-id/enrollment.json      (request id)
# Personal installs write mode=personal and return — stock quattro otherwise.

OMA_CHOICE_DIR=/run/oma-id
OMA_AGENT=/usr/bin/oma-id-agent

oma_dmi_field() { cat "/sys/class/dmi/id/$1" 2>/dev/null | tr -d '\n'; }

oma_dmi_name() {
  local v m label
  v=$(oma_dmi_field sys_vendor); m=$(oma_dmi_field product_name)
  label="$v${v:+ }$m"
  [[ -z "$label" ]] && label="Device $(head -c 8 /etc/machine-id 2>/dev/null)"
  printf '%s' "$label" | tr -s ' '
}

oma_keygen() {
  [[ -x "$OMA_AGENT" ]] || { say "oma-id agent binary missing ($OMA_AGENT)"; return 1; }
  local pub
  pub=$("$OMA_AGENT" genkey --out "$OMA_CHOICE_DIR/device.key") || return 1
  printf '%s' "$pub"
}

# Device-signed status poll (agent subcommand) — the §7.2 step-4 possession
# proof that stamps key_possession_verified_at and unblocks admin acceptance.
oma_possession_ok() {
  local url="$1" rid="$2" seed="$3"
  "$OMA_AGENT" enr-status --server "$url" --key "$seed" --request-id "$rid" >/dev/null 2>&1
}

oma_keygen_and_enroll() {
  local url="$1" machine="$2"
  step "Enrolling this machine"

  local pub
  pub=$(oma_keygen) || abort "device key generation failed"

  say "Registering the reservation…"
  local resp rid
  resp=$(jq -n --arg did "$machine" --arg key "$pub" \
    --arg name "$(oma_dmi_name)" --arg man "$(oma_dmi_field sys_vendor)" \
    --arg model "$(oma_dmi_field product_name)" --arg serial "$(oma_dmi_field product_serial)" \
    --arg mid "$(head -c 32 /etc/machine-id 2>/dev/null)" \
    '{requested_device_id:$did, public_key_hex:$key, device_name:$name,
      manufacturer:$man, model:$model, serial_number:$serial, machine_id:$mid,
      disk_encryption:"planned"}' | \
    curl -sS --max-time 20 -H 'Content-Type: application/json' -X POST --data-binary @- "$url/api/v1/enrollment-requests") || {
    abort "could not reach the server to register the reservation"
  }
  rid=$(printf '%s' "$resp" | jq -r '.id // empty')
  if [[ -z "$rid" || "$rid" == "null" ]]; then
    say "Server refused the reservation: $(printf '%s' "$resp" | head -c 300)"
    abort "enrollment request rejected"
  fi
  printf '{"request_id":%s}' "$rid" >"$OMA_CHOICE_DIR/enrollment.json"

  # §7.2 step 4: possession proof (required for admin acceptance).
  say "Proving key possession to the server…"
  local attempts=0
  while [[ $attempts -lt 5 ]]; do
    if oma_possession_ok "$url" "$rid" "$OMA_CHOICE_DIR/device.key"; then
      say "Reservation #$rid registered and possession VERIFIED."
      say "The administrator can accept it in the review UI at any time;"
      say "first boot activates it."
      return 0
    fi
    attempts=$((attempts + 1))
    say "possession check #$attempts failed — retrying…"
    sleep 3
  done
  abort "could not prove key possession — acceptance would be refused"
}

oma_save_choice() {
  local mode="$1" server="$2" note="$3" device="$4"
  mkdir -p "$OMA_CHOICE_DIR"
  jq -n --arg mode "$mode" --arg server "$server" --arg note "$note" --arg device "$device" \
    '{mode: $mode, server: $server, note: $note, device: $device}' >"$OMA_CHOICE_DIR/standin-choice.json"
}

# ── main (sourced; runs inline) ─────────────────────────────────────────────
mode=$(printf 'Personal use\nSchool / work\n' |
  gum choose --header "How will this computer be used?") || abort

if [[ "$mode" == "Personal use" ]]; then
  oma_save_choice "personal" "" "personal install selected; no OMA-ID server contact" ""
  return 0 2>/dev/null || exit 0
fi

# School / work: network (quattro's live env has it after STEP 0's own check —
# here we rely on the same ethernet/wifi availability the wizard assumes; the
# reservation POST itself validates reachability).
step "Connect to your organization"
say "Enter the OMA-ID server address exactly as given by your organization."
echo
while true; do
  url=$(gum input --placeholder "https://id.example.org" --prompt "OMA-ID server> ") || abort
  if curl -sS --max-time 10 "$url/api/v1/enrollment-requests" -o /dev/null 2>&1; then
    break
  fi
  # The endpoint may 401/405 — any HTTP answer proves reachability.
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$url/api/v1/enrollment-requests" 2>/dev/null || true)
  if [[ "$code" =~ ^[0-9]+$ && "$code" != "000" ]]; then
    break
  fi
  say "Could not reach that server. Retry, or Ctrl+C to abort."
  echo
done

step "Name this machine"
say "Used as the hostname of the installed system and proposed as its"
say "device id at enrollment (the administrator can still rename it)."
echo
machine=""
while true; do
  machine=$(gum input --placeholder "workstation-1" --value "${OMA_ID_DEVICE:-workstation-1}" \
    --prompt "Machine name> ") || abort
  machine=$(printf '%s' "$machine" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
  if printf '%s' "$machine" | grep -qE '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'; then
    break
  fi
  say "Use letters, digits, and dashes (no leading or trailing dash)."
done

echo
if ! gum confirm "Set up OMA-ID management on the installed system?"; then
  oma_save_choice "work-school-personal" "$url" "server validated; user chose to continue as personal (§6.4 explicit)" "$machine"
  say "Continuing as a personal install — no OMA-ID management will be installed."
  return 0 2>/dev/null || exit 0
fi

oma_keygen_and_enroll "$url" "$machine"
oma_save_choice "work-school" "$url" "reservation registered at install; first boot activates it" "$machine"
