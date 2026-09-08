# frozen_string_literal: true

module Api
  module V1
    # Lab lease-issuance endpoint (plan §11.4 device/login authorization,
    # P2/P3 stand-in). Issues an ed25519-signed lease in the agent's store
    # file shape so the response drops straight into
    # `fake_agent --store <file> --issuer-key <hex>`.
    #
    # Gating: `Authorization: Bearer <OMA_ID_LEASE_TOKEN>` — a lab stand-in
    # for the enrollment transaction (plan §6.2). An unset token disables
    # the endpoint entirely (503 fail-closed); a wrong token is a bare 401
    # with no detail. The P3 enrollment transaction replaces this gate.
    #
    # Issuer policy enforced here (plan §9.2/§9.3):
    # - the issuer assigns the revocation epoch, strictly increasing per
    #   (subject, device) pair;
    # - leases are bounded (24h maximum validity — the §9.2 offline window);
    # - every issuance is recorded (IssuedLease audit trail).
    class DeviceLeasesController < ApplicationController
      # Bearer-token authenticated JSON API; no browser session is involved.
      # Device credentials are separate from user credentials (§18), so the
      # P1-a session requirement is skipped — the token IS the gate.
      skip_before_action :require_authentication
      skip_before_action :verify_authenticity_token, raise: false

      MAX_DURATION_SECONDS = 24 * 60 * 60       # §9.2 offline window
      DEFAULT_DURATION_SECONDS = 60 * 60
      CLOCK_SKEW_SECONDS = 60
      KNOWN_OPERATIONS = %w[Login Unlock Elevate RemoteLogin].freeze

      before_action :require_issuance_configured
      before_action :require_bearer_token

      # POST /api/v1/device/leases
      #
      # Request JSON: subject_id, device_id, operations (array),
      # duration_seconds (optional, default 3600, max 86400).
      def create
        params = create_params
        payload, signature_hex = issue_lease(params)

        issued = IssuedLease.create!(
          subject_id: params[:subject_id],
          device_id: params[:device_id],
          revocation_epoch: payload[:revocation_epoch],
          payload_json: OmaId::LeaseSigningKey.canonical_payload_json(payload),
          signature_hex:
        )

        render json: store_file_shape(payload, signature_hex, issued.revocation_epoch, active_key_id),
               status: :created
      rescue ActionController::ParameterMissing, LeaseIssueError => error
        render json: { error: error.message }, status: :bad_request
      end

      private

      class LeaseIssueError < StandardError; end

      def require_issuance_configured
        return if lease_token.present?

        render json: { error: "lease issuance not configured" },
               status: :service_unavailable
      end

      def require_bearer_token
        provided = request.authorization&.delete_prefix("Bearer ")
        return if ActiveSupport::SecurityUtils.secure_compare(
          provided.to_s, lease_token.to_s
        )

        render json: { error: "unauthorized" }, status: :unauthorized
      end

      def lease_token
        ENV["OMA_ID_LEASE_TOKEN"]
      end

      def create_params
        body = JSON.parse(request.raw_post) if request.raw_post.present?
        raise LeaseIssueError, "request body must be JSON" if body.nil?

        {
          subject_id: require_string(body, "subject_id"),
          device_id: require_string(body, "device_id"),
          operations: require_operations(body),
          duration_seconds: body.fetch("duration_seconds", DEFAULT_DURATION_SECONDS)
        }
      rescue JSON::ParserError
        raise LeaseIssueError, "request body must be valid JSON"
      end

      def require_string(body, key)
        value = body[key]
        raise LeaseIssueError, "#{key} is required" if value.blank?
        raise LeaseIssueError, "#{key} must be a string" unless value.is_a?(String)
        raise LeaseIssueError, "#{key} exceeds 128 characters" if value.length > 128

        value
      end

      def require_operations(body)
        operations = body["operations"]
        raise LeaseIssueError, "operations is required" unless operations.is_a?(Array)
        raise LeaseIssueError, "operations must not be empty" if operations.empty?

        operations.each do |name|
          unless KNOWN_OPERATIONS.include?(name)
            raise LeaseIssueError, "unknown operation #{name.to_s.inspect}"
          end
        end
        operations
      end

      def issue_lease(params)
        duration = params[:duration_seconds]
        unless duration.is_a?(Integer) && duration.positive? && duration <= MAX_DURATION_SECONDS
          raise LeaseIssueError,
                "duration_seconds must be a positive integer <= #{MAX_DURATION_SECONDS}"
        end

        now = Time.now.to_i
        payload = {
          subject_id: params[:subject_id],
          device_id: params[:device_id],
          not_before: now - CLOCK_SKEW_SECONDS,
          expires_at: now + duration,
          # The issuer owns the epoch: strictly increasing per pair (§9.3).
          revocation_epoch: IssuedLease.next_epoch_for(params[:subject_id], params[:device_id]),
          operations: params[:operations]
        }
        signature_hex = signing_key.sign(payload)
        [payload, signature_hex]
      end

      # ADR-0005: the active lease-signing key's id is stamped into the
      # issued lease and the store record, and returned so the operator can
      # verify the agent pinned the right key. The key must be registered
      # (IssuerKey row, key_id derived from the public key) — an unregistered
      # signing key is a configuration error and fails closed.
      def active_key_id
        public_key_hex = signing_key.verify_key_hex
        # Idempotent: re-registering the same key returns the existing row
        # (the endpoint may be hit many times under one active key).
        existing = IssuerKey.find_by(purpose: IssuerKey::PURPOSE, key_id: IssuerKey.derive_key_id(public_key_hex))
        return existing.key_id if existing

        IssuerKey.register!(public_key_hex:, state: "active").key_id
      end

      def signing_key
        @signing_key ||= OmaId::LeaseSigningKey.from_seed_hex(
          ENV.fetch("OMA_ID_ISSUER_SEED", OmaId::LeaseSigningKey.lab_seed_hex)
        )
      end

      # The response IS the agent's store file: drop it into a file and run
      # `fake_agent --store <file> --issuer-key <hex>` (the pinned key is the
      # issuer's verify key; fetch it once with a token-less GET? No — it is
      # returned here under `issuer_verify_key_hex` for the lab flow).
      def store_file_shape(payload, signature_hex, epoch, key_id)
        {
          version: 2,
          high_water_revocation_epoch: epoch,
          leases: [
            {
              payload:,
              signature: signature_hex,
              key_id:,
              received_at: Time.now.to_i
            }
          ],
          issuer_verify_key_hex: signing_key.verify_key_hex,
          key_id:
        }
      end
    end
  end
end