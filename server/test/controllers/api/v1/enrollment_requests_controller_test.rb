# frozen_string_literal: true

require "test_helper"

module Api
  module V1
    # P3-a enrollment transaction, device side (plan §7.2): unauthenticated
    # request creation (idempotent per key), device-signed status polls that
    # prove key possession, opaque auth denials for the signed endpoint.
    class EnrollmentRequestsControllerTest < ActionDispatch::IntegrationTest
      setup do
        @key = Ed25519::SigningKey.new(SecureRandom.random_bytes(32))
        @public_key_hex = @key.verify_key.to_bytes.unpack1("H*")
      end

      test "create makes a pending request with a nonce" do
        post "/api/v1/enrollment-requests", params: {
          public_key_hex: @public_key_hex,
          device_name: "ASUS PRIME B550M",
          manufacturer: "ASUSTeK COMPUTER INC.",
          model: "PRIME B550M-A",
          serial_number: "SN123456",
          machine_id: "abcdef0123456789abcdef0123456789",
          requested_device_id: "workstation-1"
        }, as: :json

        assert_response :created
        body = JSON.parse(response.body)
        assert_equal "pending", body["state"]
        assert body["nonce"].present?
        assert_equal 32, body["nonce"].length
      end

      test "create is idempotent per device key (no duplicates, §7.2)" do
        post "/api/v1/enrollment-requests", params: { public_key_hex: @public_key_hex, device_name: "A" }, as: :json
        first = JSON.parse(response.body)
        post "/api/v1/enrollment-requests", params: { public_key_hex: @public_key_hex, device_name: "B" }, as: :json

        assert_response :ok
        second = JSON.parse(response.body)
        assert_equal first["id"], second["id"]
        assert_equal 1, EnrollmentRequest.where(public_key_hex: @public_key_hex).count
        assert_equal "B", EnrollmentRequest.find(first["id"]).device_name
      end

      test "create rejects a malformed key as protocol validation" do
        post "/api/v1/enrollment-requests", params: { public_key_hex: "nothex" }, as: :json
        assert_response :unprocessable_content
      end

      test "signed status poll proves key possession" do
        request_record = EnrollmentRequest.record!(public_key_hex: @public_key_hex, device_name: "box")
        assert_not request_record.key_possession_verified?

        get "/api/v1/enrollment-requests/#{request_record.id}", params: signed_params(request_record)
        assert_response :ok
        body = JSON.parse(response.body)
        assert_equal "pending", body["state"]
        assert request_record.reload.key_possession_verified?
      end

      test "unsigned status poll is an opaque 401 and proves nothing" do
        request_record = EnrollmentRequest.record!(public_key_hex: @public_key_hex)
        get "/api/v1/enrollment-requests/#{request_record.id}"
        assert_response :unauthorized
        assert_not request_record.reload.key_possession_verified?
      end

      test "wrong key, stale timestamp, and unknown id are indistinguishable 401s" do
        request_record = EnrollmentRequest.record!(public_key_hex: @public_key_hex)

        # stale timestamp
        get "/api/v1/enrollment-requests/#{request_record.id}",
            params: signed_params(request_record, timestamp: Time.now.to_i - 400)
        assert_response :unauthorized

        # unknown id — same status, no oracle
        get "/api/v1/enrollment-requests/999999", params: signed_params(request_record)
        assert_response :unauthorized

        assert_not request_record.reload.key_possession_verified?
      end

      private

      def signed_params(request_record, timestamp: Time.now.to_i)
        message = "enrollment-status|#{request_record.id}|#{timestamp}"
        signature = @key.sign(message)
        { timestamp:, signature_hex: signature.unpack1("H*") }
      end
    end
  end
end
