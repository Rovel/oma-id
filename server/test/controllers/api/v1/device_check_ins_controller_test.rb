# frozen_string_literal: true

require "test_helper"

module Api
  module V1
    # Device check-in contract tests (plan §11.2, P2 slice): key-possession
    # authentication, lease minting bound to the device's person, key-set
    # distribution.
    class DeviceCheckInsControllerTest < ActionDispatch::IntegrationTest
      TEST_SEED = "09" * 32
      DEVICE_SEED = "ab" * 32

      setup do
        @org = organizations(:lab)
        @person = Person.create!(
          display_name: "Device Owner", role: :employee,
          password: "password1", password_confirmation: "password1"
        )
        @person.login_aliases.create!(email_address: "dev@lab.test")
        @signing = Ed25519::SigningKey.new([DEVICE_SEED].pack("H*"))
        @device = Device.create!(
          device_id: "test-device-1",
          person: @person,
          public_key_hex: @signing.verify_key.to_bytes.unpack1("H*"),
          state: "active"
        )
      end

      def signed_check_in(device_id: "test-device-1", seed: DEVICE_SEED, timestamp: Time.now.to_i)
        message = "#{device_id}|#{timestamp}"
        signature = Ed25519::SigningKey.new([seed].pack("H*")).sign(message).unpack1("H*")
        post "/api/v1/device/check-ins",
             params: { device_id:, timestamp:, signature_hex: signature }.to_json,
             headers: { "CONTENT_TYPE" => "application/json" }
      end

      test "check-in with a valid device signature mints a bound signed lease" do
        freeze_time
        with_issuer_seed do
          signed_check_in
          assert_response :success

          body = JSON.parse(@response.body)
          lease = body["leases"].first
          payload = lease["payload"]
          assert_equal "person-#{@person.id}", payload["subject_id"]
          assert_equal "test-device-1", payload["device_id"]
          assert_equal now - 60, payload["not_before"]
          assert_equal now + 24 * 60 * 60, payload["expires_at"]
          assert_equal %w[Login Unlock], payload["operations"]

          # The signature verifies with the lease issuer key over the
          # canonical bytes (the same contract the Rust verifier enforces).
          key = OmaId::LeaseSigningKey.from_seed_hex(TEST_SEED)
          canonical_payload = payload.transform_values { |v| v.is_a?(Array) ? v.map(&:to_s) : v }
                                     .transform_keys(&:to_sym)
          assert key.verify(canonical_payload, lease["signature"])

          # ADR-0005 fleet distribution: the response carries the pinned
          # issuer key set.
          assert_not_empty body["issuer_keys"]
          assert body["issuer_keys"].all? { |k| %w[key_id public_key_hex state].all? { |f| k.key?(f) } }

          # Check-in is recorded.
          assert_not_nil @device.reload.last_check_in_at
          assert AuditEvent.where(action: "device.check_in", result: "success").exists?
        end
      end

      test "unknown device is a bare 401 (no oracle)" do
        with_issuer_seed do
          signed_check_in(seed: "cd" * 32) # unregistered key
          assert_response :unauthorized
        end
      end

      test "revoked device is a bare 401 (no oracle)" do
        @device.update!(state: "revoked")
        with_issuer_seed do
          signed_check_in
          assert_response :unauthorized
        end
      end

      test "stale timestamp (replay window) is rejected" do
        with_issuer_seed do
          signed_check_in(timestamp: Time.now.to_i - 400)
          assert_response :unauthorized
        end
      end

      test "a signature that fails verification is rejected" do
        with_issuer_seed do
          signed_check_in(seed: "cd" * 32) # wrong key for the registered device
          assert_response :unauthorized
        end
      end

      private

      def with_issuer_seed
        ENV["OMA_ID_ISSUER_SEED"] = TEST_SEED
        yield
      ensure
        ENV.delete("OMA_ID_ISSUER_SEED")
      end

      def now
        Time.now.to_i
      end
    end
  end
end