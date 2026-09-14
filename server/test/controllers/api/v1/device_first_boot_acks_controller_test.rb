# frozen_string_literal: true

require "test_helper"

module Api
  module V1
    # First-boot baseline evidence ack (docs/p0/installer-enrollment.md §7.2
    # step 8): a signed POST that records provisioning completion. Requires an
    # ACTIVE device (must have activated on first check-in first).
    class DeviceFirstBootAcksControllerTest < ActionDispatch::IntegrationTest
      DEVICE_SEED = "cd" * 32

      setup do
        @person = Person.create!(
          display_name: "Ack Owner", role: :employee,
          password: "password1", password_confirmation: "password1"
        )
        @person.login_aliases.create!(email_address: "ack@lab.test")
        @signing = Ed25519::SigningKey.new([DEVICE_SEED].pack("H*"))
        @device = Device.create!(
          device_id: "ack-device-1", person: @person,
          public_key_hex: @signing.verify_key.to_bytes.unpack1("H*"),
          state: "active", first_boot_acknowledged_at: nil
        )
      end

      def signed_ack(timestamp: Time.now.to_i, provisioning: "owner")
        message = "#{@device.device_id}|#{timestamp}"
        signature = @signing.sign(message).unpack1("H*")
        post "/api/v1/device/first-boot-acks",
             params: { device_id: @device.device_id, timestamp:, signature_hex: signature, provisioning: }.to_json,
             headers: { "CONTENT_TYPE" => "application/json" }
      end

      test "a signed first-boot ack records the evidence and stamps the device" do
        assert_nil @device.first_boot_acknowledged_at
        signed_ack
        assert_response :ok
        assert_equal "ok", JSON.parse(response.body)["status"]
        assert @device.reload.first_boot_acknowledged_at.present?
        assert AuditEvent.where(action: "device.first_boot", target: @device.device_id).exists?
      end

      test "a pending (not yet activated) device is refused" do
        @device.update!(state: "pending")
        signed_ack
        assert_response :unauthorized
      end

      test "an unsigned ack is an opaque 401" do
        post "/api/v1/device/first-boot-acks", params: {}.to_json,
             headers: { "CONTENT_TYPE" => "application/json" }
        assert_response :unauthorized
        assert_nil @device.reload.first_boot_acknowledged_at
      end
    end
  end
end
