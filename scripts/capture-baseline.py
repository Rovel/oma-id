#!/usr/bin/env python3
"""Capture upstream metadata and inspectable source without executing upstream code."""
import datetime
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache/p0"
REPOS = {
    "omarchy": ("omacom/omarchy", "quattro"),
    "omarchy-iso": ("omacom/omarchy-iso", "quattro"),
    "authd": ("canonical/authd", "HEAD"),
    "doorkeeper": ("doorkeeper-gem/doorkeeper", "HEAD"),
    "doorkeeper-openid_connect": ("doorkeeper-gem/doorkeeper-openid_connect", "HEAD"),
    "doorkeeper-device_authorization_grant": ("exop-group/doorkeeper-device_authorization_grant", "HEAD"),
    "webauthn": ("cedarcode/webauthn-ruby", "HEAD"),
    "phlex": ("phlex-ruby/phlex", "HEAD"),
    "phlex-rails": ("phlex-ruby/phlex-rails", "HEAD"),
    "ruby_ui": ("ruby-ui/ruby_ui", "HEAD"),
}
GEMS = ["rails", "doorkeeper", "doorkeeper-openid_connect",
        "doorkeeper-device_authorization_grant", "webauthn", "phlex", "phlex-rails", "ruby_ui"]


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "oma-id-p0-discovery"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def main():
    CACHE.mkdir(parents=True, exist_ok=True)
    result = {"captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status": "discovery candidates; not a supported runtime lock", "repositories": {}, "gems": {}}
    for name, (repo, ref) in REPOS.items():
        commit = json.loads(fetch(f"https://api.github.com/repos/{repo}/commits/{ref}"))
        sha = commit["sha"]
        archive_url = f"https://codeload.github.com/{repo}/tar.gz/{sha}"
        archive = fetch(archive_url)
        (CACHE / f"{name}-{sha}.tar.gz").write_bytes(archive)
        result["repositories"][name] = {"repository": repo, "requested_ref": ref,
            "commit": sha, "archive_url": archive_url,
            "archive_sha256": hashlib.sha256(archive).hexdigest()}
        print(f"Captured {name}: {sha}", flush=True)
    for name in GEMS:
        metadata = json.loads(fetch(f"https://rubygems.org/api/v1/gems/{name}.json"))
        result["gems"][name] = {key: metadata.get(key) for key in
            ("version", "sha", "licenses", "dependencies", "source_code_uri")}
    output = ROOT / "docs/p0/baseline.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
