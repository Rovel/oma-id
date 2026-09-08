# Public enrollment metadata (plan §11.4). Read-only, no secrets, no
# executable content. Fails closed (503) when the organization is not yet
# seeded, so an unconfigured server advertises nothing.
class EnrollmentMetadataController < ApplicationController
  # §11.4: public HTTPS metadata — no authentication.
  allow_unauthenticated_access only: :show

  METADATA_PROTOCOL_VERSIONS = ["0"].freeze
  # No enrollment method is live on this server slice. The Doorkeeper
  # device-grant/OIDC combination is proven in tests/interop only; wiring it
  # into this application is P2 work. Advertise nothing we do not serve.
  ENROLLMENT_METHODS = [].freeze

  def show
    organization = Organization.first
    unless organization
      render json: { error: "organization not configured" }, status: :service_unavailable
      return
    end

    render json: {
      protocol: {
        name: "oma-enrollment",
        versions: METADATA_PROTOCOL_VERSIONS
      },
      issuer: organization.issuer,
      organization: {
        name: organization.name,
        support_email: organization.support_email
      },
      enrollment_methods: ENROLLMENT_METHODS
    }
  end
end
