# Record of every lease the issuer has signed (P0 audit trail, plan §16).
# The issuer owns the revocation epoch: issuance for a (subject, device)
# pair must use a strictly increasing epoch, so a previously issued lease
# can never be silently renewed with an equal-or-older epoch.
class IssuedLease < ApplicationRecord
  validates :subject_id, :device_id, presence: true, length: { maximum: 128 }
  validates :revocation_epoch, presence: true, numericality: { only_integer: true, greater_than: 0 }
  validates :payload_json, :signature_hex, presence: true

  def self.next_epoch_for(subject_id, device_id)
    max = where(subject_id:, device_id:).maximum(:revocation_epoch) || 0
    max + 1
  end
end
