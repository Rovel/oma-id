# frozen_string_literal: true

module Lab
  class DeviceAuthorizationRequest < Doorkeeper::DeviceAuthorizationGrant::OAuth::DeviceAuthorizationRequest
    # Doorkeeper's validation registry is class-local, not inherited.
    validate :client, error: :invalid_client
    validate :scopes, error: :invalid_scope

    private

    def validate_scopes
      Doorkeeper::OAuth::Helpers::ScopeChecker.valid?(
        scope_str: scopes.to_s, server_scopes: Doorkeeper.configuration.scopes,
        app_scopes: client&.scopes, grant_type: "device_code"
      )
    end
  end

  class DeviceCodesController < Doorkeeper::DeviceAuthorizationGrant::DeviceCodesController
    private

    def authorize_response
      @authorize_response ||= DeviceAuthorizationRequest.new(
        Doorkeeper.configuration, server.client, Lab::ISSUER, server.parameters
      ).authorize
    end
  end

  module EnabledPersonBoundary
    def with_enabled_person
      FamilyLifecycle.with_person do |person|
        person.enabled ? yield : head(:unauthorized)
      end
    end
  end

  class AuthorizationsController < Doorkeeper::AuthorizationsController
    include EnabledPersonBoundary
    around_action :with_enabled_person
  end
  # Fake-person, in-process experiment. A production consent endpoint needs its
  # own authenticated browser transaction, CSRF protection, scope display and audit.
  class DeviceAuthorizationsController < Doorkeeper::DeviceAuthorizationGrant::DeviceAuthorizationsController
    include EnabledPersonBoundary
    around_action :with_enabled_person
    def deny
      device_grant_model.transaction do
        grant = device_grant_model.lock.find_by(user_code: params[:user_code])
        return head :unprocessable_entity if grant.nil? || grant.expired?

        grant.update!(denied_at: Time.now.utc)
        head :no_content
      end
    end

    def authorize
      device_grant_model.transaction do
        grant = device_grant_model.lock.find_by(user_code: params[:user_code])
        return head :unprocessable_entity if grant&.denied_at

        super
      end
    end
  end

  class TokensController < Doorkeeper::TokensController
    def create
      result = FamilyLifecycle.exchange(server.client, params) do
        begin
          issue_response
          @authorize_response
        rescue Doorkeeper::DeviceAuthorizationGrant::Errors::AuthorizationPending,
               Doorkeeper::DeviceAuthorizationGrant::Errors::SlowDown,
               Doorkeeper::DeviceAuthorizationGrant::Errors::ExpiredToken => error
          # These protocol outcomes intentionally persist polling/expiry state.
          # Unexpected errors still escape and roll back issuance plus audit.
          handle_token_exception(error)
          nil
        end
      end
      if result == :invalid_grant
        headers["Cache-Control"] = "no-store"
        headers["Pragma"] = "no-cache"
        render json: {error: "invalid_grant"}, status: :bad_request
      end
    end

    def revoke
      FamilyLifecycle.with_person do
        super
        if response.status == 200 && token && server.client && token.application_id == server.client.id
          member = FamilyMember.find_by(token_id: token.id)
          FamilyLifecycle.revoke_family!(TokenFamily.find(member.family_id), "revoked", token.id) if member
        end
      end
    end

    private

    def issue_response
      if params[:grant_type] == "urn:ietf:params:oauth:grant-type:device_code"
        grant = Doorkeeper::DeviceAuthorizationGrant::DeviceGrant.by_device_code(params[:device_code])
        # Let the upstream implementation reject invalid or mismatched clients.
        if grant&.denied_at && server.client && grant.application_id == server.client.id
          headers["Cache-Control"] = "no-store"
          headers["Pragma"] = "no-cache"
          return render json: {error: grant.expired? ? "expired_token" : "access_denied"}, status: :bad_request
        end
      end
      # Invoke the upstream endpoint implementation, keeping issuance and response
      # serialization inside the same transaction as membership and audit writes.
      Doorkeeper::TokensController.instance_method(:create).bind_call(self)
    end
  end
end
