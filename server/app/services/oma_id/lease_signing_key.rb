# frozen_string_literal: true

# OMA-ID lease signing (issuer side, lab slice).
#
# Signs LeasePayload structures with the agent-side canonical encoding pinned
# in native/crates/oma-id-agent-store (lease-v1): compact JSON, fields in the
# schema order subject_id, device_id, not_before, expires_at,
# revocation_epoch, operations. The agent verifies with ed25519-dalek
# verify_strict, so both encoders must produce byte-identical output; the
# cross-language fixture in protocol/lease-v1/ pins this contract.
#
# Lab boundaries: fixed-seed keys from OMA_ID_ISSUER_SEED (hex) are for
# experiments only. Key ceremony, storage, and rotation are owner ADR
# decisions (oma-id_plan.md §5.3 — lease-signing keys are a separate key
# purpose and must never reuse OIDC signing material).

module OmaId
  class LeaseSigningKey
    OPERATION_NAMES = %w[Login Unlock Elevate RemoteLogin].freeze

    class Error < StandardError; end

    attr_reader :signing_key, :verify_key_hex

    def initialize(signing_key)
      @signing_key = signing_key
      @verify_key_hex = signing_key.verify_key.to_bytes.unpack1("H*")
    end

    def self.from_seed_hex(seed_hex)
      seed = [seed_hex].pack("H*")
      raise Error, "issuer seed must be 32 bytes" unless seed.bytesize == 32

      new(Ed25519::SigningKey.new(seed))
    end

    def self.lab_seed_hex
      # Lab-only fixed seed for experiments and fixtures. Never production.
      "0" * 64
    end

    # LeasePayload = Hash with symbol keys matching
    # oma-id-agent-store::LeasePayload:
    #   subject_id, device_id, not_before, expires_at, revocation_epoch,
    #   operations (array of operation names in issuer-supplied order).
    #
    # Returns the canonical JSON bytes (lease-v1): compact, schema field
    # order, defensively escaped strings. Must stay byte-identical to
    # canonical_payload_json in the store crate.
    def self.canonical_payload_json(payload)
      operations = payload.fetch(:operations)
      validate_operations!(operations)
      validate_uint!(:not_before, payload.fetch(:not_before))
      validate_uint!(:expires_at, payload.fetch(:expires_at))
      validate_uint!(:revocation_epoch, payload.fetch(:revocation_epoch))

      out = +"{"
      out << json_string("subject_id") << ":" << json_string(payload.fetch(:subject_id).to_s)
      out << "," << json_string("device_id") << ":" << json_string(payload.fetch(:device_id).to_s)
      out << "," << json_string("not_before") << ":" << payload.fetch(:not_before).to_s
      out << "," << json_string("expires_at") << ":" << payload.fetch(:expires_at).to_s
      out << "," << json_string("revocation_epoch") << ":" << payload.fetch(:revocation_epoch).to_s
      out << "," << json_string("operations") << ":["
      out << operations.map { |name| json_string(name.to_s) }.join(",")
      out << "]}"
      out.b
    end

    def self.json_string(value)
      escaped = value.gsub(/["\\\x00-\x1f]/) do |char|
        case char
        when '"' then '\\"'
        when "\\" then "\\\\"
        else format("\\u%04x", char.ord)
        end
      end
      "\"#{escaped}\""
    end

    def self.validate_operations!(operations)
      raise Error, "operations must not be empty" if operations.empty?

      operations.each do |name|
        unless OPERATION_NAMES.include?(name.to_s)
          raise Error, "unknown operation #{name.to_s.inspect}"
        end
      end
    end

    def self.validate_uint!(key, value)
      unless value.is_a?(Integer) && value >= 0
        raise Error, "#{key} must be a non-negative integer, got #{value.inspect}"
      end
    end

    # Sign a payload: returns the hex ed25519 signature over the canonical
    # bytes. The signature covers the exact bytes the agent will verify.
    def sign(payload)
      @signing_key.sign(canonical_bytes(payload)).unpack1("H*")
    end

    # Verify a payload + hex signature against this key's public half
    # (issuer-side self-check; the agent is the authoritative verifier).
    def verify(payload, signature_hex)
      @signing_key.verify_key.verify([signature_hex].pack("H*"), canonical_bytes(payload))
      true
    rescue Ed25519::VerifyError
      false
    end

    private

    def canonical_bytes(payload)
      self.class.canonical_payload_json(payload)
    end
  end
end
