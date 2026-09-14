# frozen_string_literal: true

module Api
  module V1
    # First-boot baseline evidence acknowledgement (docs/p0/installer-enrollment.md,
    # plan §7.2 step 8): after provisioning succeeds on the installed system, the
    # bootstrapper reports back so the server records activation completion in the
    # audit trail. Signed like a check-in (device key possession over
    # "device_id|timestamp", ±300s window).
    class DeviceFirstBootAcksController < ActionController::Base
      skip_before_action :verify_authenticity_token, raise: false

      REPLAY_WINDOW_SECONDS = 300

      # POST /api/v1/device/first-boot-acks
      def create
        device = Device.find_by(device_id: body["device_id"].to_s)
        return render(json: { error: "unauthorized" }, status: :unauthorized) unless device&.active?
        return render(json: { error: "unauthorized" }, status: :unauthorized) unless verify_device_signature(device, body)

        device.update!(first_boot_acknowledged_at: Time.current)
        AuditEvent.record!(
          actor: device.device_id, action: "device.first_boot", target: device.device_id,
          result: "success",
          metadata: { provisioning: body["provisioning"].to_s[0, 64].presence }
        )
        render json: { status: "ok" }
      end

      private

      def body
        JSON.parse(request.raw_post)
      rescue JSON::ParserError
        {}
      end

      def verify_device_signature(device, body)
        timestamp = Integer(body["timestamp"])
        return false if (Time.now.to_i - timestamp).abs > REPLAY_WINDOW_SECONDS

        message = "#{body["device_id"]}|#{timestamp}"
        Ed25519::VerifyKey.new([device.public_key_hex].pack("H*"))
                          .verify([body["signature_hex"].to_s].pack("H*"), message)
        true
      rescue ArgumentError, Ed25519::VerifyError, TypeError
        false
      end
    end
  end
end
