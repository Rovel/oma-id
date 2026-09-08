# frozen_string_literal: true

require "test_helper"

module Api
  module V1
    # Lab lease-issuance contract tests. The gate is a bearer token stand-in
    # for the P3 enrollment transaction; the issuer owns the epoch and the
    # validity bound (§9.2/§9.3).
    class DeviceLeasesControllerTest < ActionDispatch::IntegrationTest
      TEST_SEED = "09" * 32
      TEST_TOKEN = "lab-lease-token"

      setup do
        @org = organizations(:lab)
      end

      def issue_request(token: TEST_TOKEN, body: default_body, headers: {})
        request_headers = { "CONTENT_TYPE" => "application/json" }.merge(headers)
        if token
          request_headers["Authorization"] = "Bearer #{token}"
        end
        post "/api/v1/device/leases",
             params: body.is_a?(String) ? body : body.to_json,
             headers: request_headers
      end

      def default_body
        {
          subject_id: "person-1",
          device_id: "device-1",
          operations: %w[Login Unlock],
          duration_seconds: 3600
        }
      end

      test "returns 503 fail-closed when issuance is not configured" do
        issue_request(token: nil)
        assert_response :service_unavailable
        assert_equal({ "error" => "lease issuance not configured" }, JSON.parse(@response.body))
      end

      test "returns a bare 401 on a wrong token" do
        with_lease_token(TEST_TOKEN) do
          issue_request(token: "wrong-token")
          assert_response :unauthorized
          assert_equal({ "error" => "unauthorized" }, JSON.parse(@response.body))
        end
      end

      test "issues a bounded signed lease in the agent store shape" do
        with_lease_token(TEST_TOKEN) do
          freeze_time
          issue_request
          assert_response :created

          body = JSON.parse(@response.body)
          assert_equal 1, body["version"]
          lease = body["leases"].first
          payload = lease["payload"]

          # Issuer policy: bounded validity, skew, issuer-owned epoch.
          assert_equal now - 60, payload["not_before"]
          assert_equal now + 3600, payload["expires_at"]
          assert_equal 1, payload["revocation_epoch"]
          assert_equal %w[Login Unlock], payload["operations"]

          # The signature verifies against the issuer key over the canonical
          # bytes — the exact contract the Rust verifier enforces.
          key = OmaId::LeaseSigningKey.from_seed_hex(TEST_SEED)
          canonical_payload = payload.transform_values { |v| v.is_a?(Array) ? v.map(&:to_s) : v }
            .transform_keys(&:to_sym)
          assert key.verify(canonical_payload, lease["signature"]),
                 "issued lease signature must self-verify"
          assert_equal(
            OmaId::LeaseSigningKey.canonical_payload_json(canonical_payload),
            lease["payload"].then { |p| OmaId::LeaseSigningKey.canonical_payload_json(canonical_payload) }
          )

          # The issuance is recorded for epoch monotonicity + audit.
          issued = IssuedLease.find_by!(subject_id: "person-1", device_id: "device-1")
          assert_equal 1, issued.revocation_epoch
        end
      end

      test "epoch strictly increases per subject/device pair" do
        with_lease_token(TEST_TOKEN) do
          issue_request
          assert_response :created
          issue_request(body: default_body.merge(duration_seconds: 7200))
          assert_response :created

          epochs = IssuedLease.where(subject_id: "person-1", device_id: "device-1")
                              .order(:revocation_epoch).pluck(:revocation_epoch)
          assert_equal [1, 2], epochs

          body = JSON.parse(@response.body)
          assert_equal 2, body["high_water_revocation_epoch"]
        end
      end

      test "duration above the 24h window is rejected" do
        with_lease_token(TEST_TOKEN) do
          issue_request(body: default_body.merge(duration_seconds: 25 * 60 * 60))
          assert_response :bad_request
          assert_match(/duration_seconds/, @response.body)
        end
      end

      test "unknown operations and oversized identifiers are rejected" do
        with_lease_token(TEST_TOKEN) do
          issue_request(body: default_body.merge(operations: ["Teleport"]))
          assert_response :bad_request
          assert_match(/unknown operation/, @response.body)

          issue_request(body: default_body.merge(subject_id: "x" * 129))
          assert_response :bad_request
          assert_match(/exceeds 128/, @response.body)
        end
      end

      test "malformed JSON is a bad request, not a 500" do
        with_lease_token(TEST_TOKEN) do
          issue_request(body: "{not json", headers: {})
          assert_response :bad_request
        end
      end

      private

      def with_lease_token(token)
        ENV["OMA_ID_LEASE_TOKEN"] = token
        # Pin the fixture seed so issued signatures are verifiable with the
        # fixture key (and reproducible end to end).
        ENV["OMA_ID_ISSUER_SEED"] = TEST_SEED
        yield
      ensure
        ENV.delete("OMA_ID_LEASE_TOKEN")
        ENV.delete("OMA_ID_ISSUER_SEED")
      end

      def now
        Time.now.to_i
      end
    end
  end
end