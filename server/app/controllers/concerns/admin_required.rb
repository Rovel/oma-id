# frozen_string_literal: true

# Administrator-only surface (plan §21: strong admin separation). Owner or
# identity_admin role required; everyone else is redirected to the front.
module AdminRequired
  extend ActiveSupport::Concern

  included do
    before_action :require_identity_admin
  end

  private

  def require_identity_admin
    person = Current.person
    allowed = person.respond_to?(:owner?) && (person.owner? || person.identity_admin?)
    redirect_to root_path, alert: "Administrator role required." unless allowed
  end

  def actor_name
    "admin:#{Current.person&.primary_email || 'unknown'}"
  end
end
