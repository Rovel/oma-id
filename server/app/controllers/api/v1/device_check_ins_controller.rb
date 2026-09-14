# frozen_string_literal: true

module Api
  module V1
    # Device check-in (plan §11.2): an enrolled device authenticates with its
    # key pair, receives fresh signed leases, the pinned issuer key set
    # (ADR-0005 distribution), and the current revocation epoch. Replaces
    # the bearer-token lab flow as the operational renewal path.
    #
    # P2 boundary: request authentication is a device signature over
    # "device_id|timestamp" with a ±300s replay window; §7.4 mTLS/device-CA
    # and server-issued challenges are later hardening. Enrollment is
    # technician pre-provisioning (§6.3) — the full transaction is P3.
    class DeviceCheckInsController < ActionController::Base
      skip_before_action :verify_authenticity_token, raise: false

      REPLAY_WINDOW_SECONDS = 300

      # POST /api/v1/device/check-ins
      #
      # Reserve-then-activate (§6.3/§7.2 step 5): a PENDING device is the
      # reservation bound to its person and key at acceptance; the first
      # signed check-in proves the installed machine holds the key and flips
      # it to active, delivering the one-time first-login bootstrap
      # credential (single-use — nulled on delivery).
      def create
        device = Device.find_by(device_id: body["device_id"].to_s)
        # Unknown, revoked, and otherwise-not-usable devices are
        # indistinguishable (no oracle). Only pending/active can be tried.
        return render(json: { error: "unauthorized" }, status: :unauthorized) unless device && (device.pending? || device.active?)
        return render(json: { error: "unauthorized" }, status: :unauthorized) unless verify_device_signature(device, body)

        activation = device.pending?
        device.activate! if activation
        device.update!(last_check_in_at: Time.current)
        AuditEvent.record!(actor: device.device_id,
                           action: activation ? "device.activate" : "device.check_in",
                           result: "success")

        response = check_in_response(device)
        if activation
          credential = device.bootstrap_credential
          device.update!(bootstrap_delivered_at: Time.current, bootstrap_credential: nil)
          response[:bootstrap] = { credential:, rotate: true } if credential
        end
        render json: response
      end

      private

      def body
        @body ||= JSON.parse(request.raw_post)
      rescue JSON::ParserError
        {}
      end

      def verify_device_signature(device, body)
        timestamp = Integer(body["timestamp"])
        return false if (Time.now.to_i - timestamp).abs > REPLAY_WINDOW_SECONDS

        message = "#{body["device_id"]}|#{timestamp}"
        Ed25519::VerifyKey.new([device.public_key_hex].pack("H*"))
                          .verify([body["signature_hex"]].pack("H*"), message)
        true
      rescue ArgumentError, Ed25519::VerifyError, TypeError
        false
      end

      # Mint a fresh signed lease for the device's assigned person. The
      # issuer owns the epoch (§9.3); the device_id doubles as the lease's
      # device binding.
      def check_in_response(device)
        now = Time.now.to_i
        subject = "person-#{device.person_id}"
        payload = {
          subject_id: subject,
          device_id: device.device_id,
          not_before: now - 60,
          expires_at: now + 24 * 60 * 60, # §9.2 offline window
          revocation_epoch: IssuedLease.next_epoch_for(subject, device.device_id),
          operations: %w[Login Unlock]
        }
        signature_hex = signing_key.sign(payload)
        key_id = active_key_id

        IssuedLease.create!(
          subject_id: payload[:subject_id],
          device_id: payload[:device_id],
          revocation_epoch: payload[:revocation_epoch],
          payload_json: OmaId::LeaseSigningKey.canonical_payload_json(payload),
          signature_hex:
        )

        posix = PosixIdentityMapping.find_by(person: device.person)
        {
          version: 2,
          high_water_revocation_epoch: payload[:revocation_epoch],
          leases: [ { payload:, signature: signature_hex, key_id:, received_at: now } ],
          issuer_verify_key_hex: signing_key.verify_key_hex,
          key_id:,
          issuer_keys: IssuerKey.where(purpose: IssuerKey::PURPOSE).map do |row|
            { key_id: row.key_id, public_key_hex: row.public_key_hex, state: row.state }
          end,
          posix: posix && {
            username: posix.username,
            uid: posix.uid,
            gid: posix.gid,
            home: posix.home,
            shell: posix.shell,
            full_name: posix.full_name
          }
        }
      end

      def active_key_id
        public_key_hex = signing_key.verify_key_hex
        existing = IssuerKey.find_by(purpose: IssuerKey::PURPOSE, key_id: IssuerKey.derive_key_id(public_key_hex))
        return existing.key_id if existing

        IssuerKey.register!(public_key_hex:, state: "active").key_id
      end

      def signing_key
        @signing_key ||= OmaId::LeaseSigningKey.from_seed_hex(
          ENV.fetch("OMA_ID_ISSUER_SEED", OmaId::LeaseSigningKey.lab_seed_hex)
        )
      end

      # The lease epoch is issuer-owned and strictly increasing per
      # (subject, device) pair (§9.3). A separate deployment-wide revocation
      # epoch arrives with §9.1 revocation polling (P4).
    end
  end
end