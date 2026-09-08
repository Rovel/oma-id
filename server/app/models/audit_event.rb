# §16: audit events record actor, action, target, result and metadata with
# secrets redacted. P1-a records them synchronously; the transactional outbox
# (§16) is a later slice.
class AuditEvent < ApplicationRecord
  ACTORS = %w[anonymous bootstrap].freeze

  validates :actor, :action, :result, presence: true

  def self.record!(actor:, action:, target: nil, result:, metadata: {})
    create!(actor:, action:, target:, result:, metadata:)
  rescue ActiveRecord::RecordInvalid => error
    # An audit failure must never break the caller's security decision path
    # silently — re-raise in test/development, log loudly in production.
    raise error unless Rails.env.production?

    Rails.logger.error("AUDIT WRITE FAILED: #{error.message}")
  end
end
