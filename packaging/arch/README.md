# Arch packaging definitions (plan §23)

P0/P2 scope: reviewed package *shapes*, proven by building in the pinned
Arch container. Publishing to a real repository (an omarchy offline mirror
or a repo server) is later work (P4).

## Layout

- `oma-id-agent.service` — systemd unit for the agent (§11.1 hardening that
  still allows provisioning; the privileged-helper split arrives with P4
  and enables stricter isolation).
- `oma-id-agent.json.example` — the config shape; `/etc/oma-id-agent.json`
  is per-deployment data (never overwritten by the package).
- `PKGBUILD` — `oma-id-agent` and `pam-oma-id` packages from the pinned
  workspace.

## Building (pinned Arch container)

The PKGBUILD expects the workspace under `native/` next to itself, exactly
as the ISO build context provides it:

    # inside an Arch container with rust/cargo:
    makepkg -f

## What this is NOT

Not published packages, not an installed-system distribution yet. The
packages are exercised through the omarchy-iso standin layer and the
container matrix. Repository publishing + signed packages are P4/P8 with
the signing-key decisions of §13.
