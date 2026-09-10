# frozen_string_literal: true

module Api
  module V1
    # P3-a enrollment transaction, device side (plan §7.2, §7.3):
    #
    #   POST /api/v1/enrollment-requests
    #     An unauthenticated device posts its public key + hardware identity.
    #     Creates (or idempotently refreshes) a `pending` request. No
    #     organizational access is granted (§7.3).
    #
    #   GET /api/v1/enrollment-requests/:id
    #     Signed with the DEVICE key over "enrollment-status|<id>|<timestamp>"
    #     (±300s replay window, same shape as check-ins). This is the §7.2
    #     step-4 key-possession proof in minimal form: a verified poll stamps
    #     key_possession_verified_at, which the administrator sees in the
    #     approval UI; acceptance is refused without it. The response carries
    #     the state, the nonce, and — once accepted — the assigned device_id
    #     (the agent adopts it for check-ins).
    class EnrollmentRequestsController < ActionController::Base
      skip_before_action :verify_authenticity_token, raise: false
      # §5.1-adjacent hygiene: the unauthenticated first-contact endpoint is
      # flood-limited (per IP) so pending-request spam cannot bury the admin
      # review queue.
      rate_limit to: 30, within: 3.minutes, only: :create

      REPLAY_WINDOW_SECONDS = 300

      # POST /api/v1/enrollment-requests
      def create
        attrs = {
          device_name: body["device_name"].to_s[0, 200].presence,
          manufacturer: body["manufacturer"].to_s[0, 200].presence,
          model: body["model"].to_s[0, 200].presence,
          serial_number: body["serial_number"].to_s[0, 200].presence,
          machine_id: body["machine_id"].to_s[0, 64].presence,
          requested_device_id: body["requested_device_id"].to_s[0, 128].presence
        }
        key = body["public_key_hex"].to_s.strip.downcase
        unless key.match?(/\A[0-9a-f]{64}\z/)
          # Protocol validation only — this is the one case that may say why.
          return render json: { error: "invalid public_key_hex" }, status: :unprocessable_content
        end

        # §7.3: a pending request has no organizational access — creation is
        # deliberately unauthenticated (first contact), everything after is
        # signed or admin-gated. Rate-limited against request flooding.
        request_record = EnrollmentRequest.record!(attrs.merge(public_key_hex: key))
        render json: { id: request_record.id, state: request_record.state,
                       nonce: request_record.nonce },
               status: request_record.saved_change_to_id? ? :created : :ok
      end

      # GET /api/v1/enrollment-requests/:id (device-signed)
      def show
        request_record = EnrollmentRequest.find_by(id: params[:id].to_i)
        # Unknown and known-but-unverified are indistinguishable (no oracle).
        return render json: { error: "unauthorized" }, status: :unauthorized unless request_record
        return render json: { error: "unauthorized" }, status: :unauthorized unless verify_device_signature(request_record, body)

        request_record.mark_key_possession_verified!

        payload = { state: request_record.state, nonce: request_record.nonce }
        if request_record.accepted?
          payload[:device] = { device_id: request_record.device.device_id }
        end
        render json: payload
      end

      private

      def body
        # POST bodies carry the enrollment details; the signed GET carries
        # its proof in the query string, so both shapes land here.
        JSON.parse(request.raw_post || "")
      rescue JSON::ParserError
        request.query_parameters
      end

      def verify_device_signature(request_record, params)
        timestamp = Integer(params["timestamp"])
        return false if (Time.now.to_i - timestamp).abs > REPLAY_WINDOW_SECONDS

        message = "enrollment-status|#{request_record.id}|#{timestamp}"
        Ed25519::VerifyKey.new([request_record.public_key_hex].pack("H*"))
                          .verify([params["signature_hex"].to_s].pack("H*"), message)
        true
      rescue ArgumentError, Ed25519::VerifyError, TypeError
        false
      end
    end
  end
end
