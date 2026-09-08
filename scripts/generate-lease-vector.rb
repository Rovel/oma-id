#!/usr/bin/env ruby
# frozen_string_literal: true

# Regenerates protocol/lease-v1/rails-signs-vector.json: the Rails-signed
# lease fixture the Rust agent suite verifies on every CI run
# (oma-id-agent-store/tests/rails_vector.rs). Deterministic: fixed lab seed
# and payload. Lab-only key material — never production.
#
# Usage: cd server && bin/rails runner ../scripts/generate-lease-vector.rb
# (run from server/ the path is scripts/generate-lease-vector.rb; the
# generated file lands in the repository root's protocol/ directory).

require "json"
require "fileutils"

REPO_ROOT = File.expand_path("..", __dir__)
OUT_PATH = File.join(REPO_ROOT, "protocol/lease-v1/rails-signs-vector.json")

key = OmaId::LeaseSigningKey.from_seed_hex("09" * 32)
payload = {
  subject_id: "person-1",
  device_id: "device-1",
  not_before: 1000,
  expires_at: 2000,
  revocation_epoch: 7,
  operations: %w[Login Unlock]
}
signature = key.sign(payload)
canonical = OmaId::LeaseSigningKey.canonical_payload_json(payload)

# Issuer-side self-check before writing the fixture.
raise "issuer signature failed self-verification" unless key.verify(payload, signature)

vector = {
  contract: "oma-lease-v1",
  canonical_encoding: canonical.force_encoding("UTF-8"),
  public_key_hex: key.verify_key_hex,
  payload:,
  signature_hex: signature
}

FileUtils.mkdir_p(File.dirname(OUT_PATH))
File.write(OUT_PATH, JSON.pretty_generate(vector) + "\n")
puts "wrote #{OUT_PATH}"
