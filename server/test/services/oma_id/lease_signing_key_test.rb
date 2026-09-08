# frozen_string_literal: true

require "test_helper"

module OmaId
  # Lease-signing contract tests (protocol/lease-v1). The authoritative
  # verifier is the Rust agent (oma-id-agent-store); the committed fixture
  # protocol/lease-v1/rails-signs-vector.json is verified there on every CI
  # run. These tests pin the Rails side: canonical encoding, determinism,
  # self-verification, and input validation.
  class LeaseSigningKeyTest < ActiveSupport::TestCase
    TEST_SEED = "09" * 32
    EXPECTED_VERIFY_KEY = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
    EXPECTED_CANONICAL =
      '{"subject_id":"person-1","device_id":"device-1","not_before":1000,' \
      '"expires_at":2000,"revocation_epoch":7,"operations":["Login","Unlock"]}'

    def payload
      {
        subject_id: "person-1",
        device_id: "device-1",
        not_before: 1000,
        expires_at: 2000,
        revocation_epoch: 7,
        operations: %w[Login Unlock]
      }
    end

    test "fixed lab seed yields the pinned verify key" do
      key = LeaseSigningKey.from_seed_hex(TEST_SEED)
      assert_equal EXPECTED_VERIFY_KEY, key.verify_key_hex
    end

    test "canonical encoding is byte-exact and deterministic" do
      assert_equal EXPECTED_CANONICAL, LeaseSigningKey.canonical_payload_json(payload)
      assert_equal EXPECTED_CANONICAL, LeaseSigningKey.canonical_payload_json(payload)
    end

    test "sign is deterministic and self-verifies" do
      key = LeaseSigningKey.from_seed_hex(TEST_SEED)
      signature = key.sign(payload)
      assert_equal 128, signature.length
      assert key.verify(payload, signature), "issuer self-verification must pass"
      assert_equal signature, key.sign(payload), "signing must be deterministic"
    end

    test "tampered payload fails verification" do
      key = LeaseSigningKey.from_seed_hex(TEST_SEED)
      signature = key.sign(payload)
      tampered = payload.merge(revocation_epoch: 99)
      assert_not key.verify(tampered, signature), "epoch escalation must be caught"
    end

    test "rejects unknown and empty operations before signing" do
      key = LeaseSigningKey.from_seed_hex(TEST_SEED)
      assert_raises(LeaseSigningKey::Error) do
        LeaseSigningKey.canonical_payload_json(payload.merge(operations: ["Teleport"]))
      end
      assert_raises(LeaseSigningKey::Error) do
        LeaseSigningKey.canonical_payload_json(payload.merge(operations: []))
      end
    end

    test "rejects negative and non-integer times before signing" do
      key = LeaseSigningKey.from_seed_hex(TEST_SEED)
      assert_raises(LeaseSigningKey::Error) do
        LeaseSigningKey.canonical_payload_json(payload.merge(not_before: -1))
      end
      assert_raises(LeaseSigningKey::Error) do
        LeaseSigningKey.canonical_payload_json(payload.merge(expires_at: "2000"))
      end
    end

    test "rejects seeds that are not 32 bytes" do
      assert_raises(LeaseSigningKey::Error) do
        LeaseSigningKey.from_seed_hex("abcd")
      end
    end

    test "committed rails vector fixture matches this suite's output" do
      vector_path = Rails.root.join("../protocol/lease-v1/rails-signs-vector.json")
      vector = JSON.parse(File.read(vector_path))
      key = LeaseSigningKey.from_seed_hex(TEST_SEED)

      assert_equal EXPECTED_VERIFY_KEY, vector["public_key_hex"]
      assert_equal EXPECTED_CANONICAL, vector["canonical_encoding"]
      assert key.verify(payload, vector["signature_hex"]),
             "the committed fixture must be reproducible by this suite"
    end
  end
end
