# One organization per deployment (ADR-0004). The issuer is canonical and
# immutable once set; display name and support contact are presentation data.
class Organization < ApplicationRecord
  validates :name, presence: true
  # P0 lab slice: http is allowed for LAN development. Real enrollment
  # requires HTTPS (oma-id_plan.md §6.2); enforcing that belongs to the P1/P2
  # boundary, not here.
  validates :issuer,
            presence: true,
            uniqueness: true,
            format: { with: %r{\Ahttps?://[^\s/]+\z} }
  validates :support_email,
            presence: true,
            format: { with: URI::MailTo::EMAIL_REGEXP }
end
