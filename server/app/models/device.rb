# A managed device (plan §7): bound to a person, identified by its key pair.
# P2 slice boundary: enrollment is technician pre-provisioning (§6.3) — an
# administrator registers the device public key out-of-band; the agent then
# proves possession by signing every check-in. The full enrollment
# transaction (pending → approved → key-proof → reserve → activate, §7.2)
# is P3 work.
class Device < ApplicationRecord
  STATES = %w[pending active quarantined revoked].freeze

  belongs_to :person

  normalizes :device_id, with: ->(d) { d.strip.downcase }

  validates :device_id,
            presence: true,
            uniqueness: true,
            length: { maximum: 128 },
            format: { with: /\A[a-z0-9][a-z0-9-]*\z/ }
  validates :public_key_hex,
            presence: true,
            length: { is: 64 },
            format: { with: /\A[0-9a-f]{64}\z/ }
  validates :state, presence: true, inclusion: { in: STATES }

  scope :active, -> { where(state: "active") }

  def active?
    state == "active"
  end
end
