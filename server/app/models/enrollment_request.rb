# frozen_string_literal: true

# P3-a enrollment request (plan §7.2, §7.3): the device's claim to be
# enrolled, created by the device itself with its public key and hardware
# identity. No organizational access while `pending` (§7.3) — acceptance is
# an administrator action bound to a person, and is only permitted after the
# device proved key possession via a signed status poll (§7.2 step 4).
#
# States (the §7.3 subset this slice implements):
#   pending  — request exists; no organizational access.
#   accepted — approved; the Device row exists and check-ins work.
#   rejected — declined; terminal for this key. The device re-posting the
#              same key gets the same rejected row; re-enrollment requires
#              the administrator to clear the request (new lifecycle, §7.3).
class EnrollmentRequest < ApplicationRecord
  STATES = %w[pending accepted rejected].freeze

  belongs_to :person, optional: true
  belongs_to :device, optional: true

  normalizes :public_key_hex, with: ->(k) { k.strip.downcase }

  validates :public_key_hex,
            presence: true,
            length: { is: 64 },
            format: { with: /\A[0-9a-f]{64}\z/ }
  validates :state, presence: true, inclusion: { in: STATES }
  validates :nonce, presence: true

  scope :pending, -> { where(state: "pending") }
  scope :recent_first, -> { order(created_at: :desc) }

  # Idempotent creation (§7.2: retries must not create duplicates): the
  # device key IS the identity, so the same key always maps to one request.
  # Hardware details are refreshed on re-post (the machine may be better
  # identified by a later boot).
  def self.record!(attributes)
    key = attributes[:public_key_hex]
    request = find_by(public_key_hex: key)
    created = request.nil?
    request ||= new(public_key_hex: key, nonce: SecureRandom.hex(16))
    request.assign_attributes(attributes.except(:public_key_hex))
    request.save!
    AuditEvent.record!(
      actor: "device:#{key[0, 16]}",
      action: "enrollment.#{created ? 'request' : 'request_refresh'}",
      target: "enrollment_request:#{request.id}",
      result: "success",
      metadata: { device_name: request.device_name, state: request.state }
    )
    request
  end

  # §7.2 step 4 (minimal form): a device-signed status poll proved private
  # key possession. Acceptance requires this.
  def mark_key_possession_verified!
    update!(key_possession_verified_at: Time.current) if key_possession_verified_at.nil?
  end

  def key_possession_verified?
    key_possession_verified_at.present?
  end

  def pending?
    state == "pending"
  end

  def accepted?
    state == "accepted"
  end

  # §7.2 steps 3-4: administrative approval, bound to the transaction, the
  # device public key, the assigned identity, and — enforced before the
  # flip — a verified key-possession proof.
  def accept!(person:, device_id:, actor:)
    raise NotReady, "key possession not verified yet" unless key_possession_verified?
    raise NotReady, "already #{state}" unless pending?

    self.transaction do
      device = OmaId::EnrollDevice.call!(person:, device_id:, public_key_hex:)
      update!(state: "accepted", person:, device:)
      AuditEvent.record!(
        actor: actor, action: "enrollment.accept", target: "enrollment_request:#{id}",
        result: "success",
        metadata: { device_id: device.device_id, person_email: person.primary_email,
                    posix_username: PosixIdentityMapping.find_by(person:)&.username }
      )
      device
    end
  end

  def reject!(actor:)
    raise NotReady, "already #{state}" unless pending?

    update!(state: "rejected")
    AuditEvent.record!(actor: actor, action: "enrollment.reject",
                       target: "enrollment_request:#{id}", result: "success")
  end

  class NotReady < StandardError; end
end
