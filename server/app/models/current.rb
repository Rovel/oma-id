class Current < ActiveSupport::CurrentAttributes
  attribute :session
  delegate :person, to: :session, allow_nil: true
end
