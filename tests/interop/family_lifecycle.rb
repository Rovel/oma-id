# frozen_string_literal: true

module Lab
  class PersonState < ActiveRecord::Base
    self.table_name = "lab_people"
  end

  class TokenFamily < ActiveRecord::Base
    self.table_name = "lab_token_families"
  end

  class FamilyMember < ActiveRecord::Base
    self.table_name = "lab_family_members"
  end

  class LifecycleEvent < ActiveRecord::Base
    self.table_name = "lab_lifecycle_events"
  end

  # PostgreSQL owns lifecycle state. The single fake person's row is the shared
  # lock for issuance, refresh, revocation, consent and disablement in this lab.
  # This intentionally favors a reviewable lock order over per-family throughput.
  module FamilyLifecycle
    module_function

    def with_person
      PersonState.transaction do
        person = PersonState.lock.find(PERSON.id)
        yield person
      end
    end

    def exchange(client, params)
      with_person do |person|
        source = case params[:grant_type]
                 when "refresh_token" then Doorkeeper::AccessToken.by_refresh_token(params[:refresh_token])
                 when "authorization_code" then Doorkeeper::AccessGrant.by_token(params[:code])
                 when "urn:ietf:params:oauth:grant-type:device_code"
                   Doorkeeper::DeviceAuthorizationGrant::DeviceGrant.by_device_code(params[:device_code])
                 end
        # Upstream authenticates/rejects unknown clients and invalid grants. Do
        # not revoke anything on a wrong-client probe, even with a stolen secret.
        next yield unless client && source && source.application_id == client.id
        # A still-pending device code has no assigned person yet.
        next :invalid_grant if source.resource_owner_id && !person.enabled
        next :invalid_grant if source.resource_owner_id && source.resource_owner_id != person.id

        parent = nil
        family = nil
        if params[:grant_type] == "refresh_token"
          parent = FamilyMember.find_by(token_id: source.id)
          next :invalid_grant unless parent # untracked credentials fail closed
          family = TokenFamily.find(parent.family_id)
          next :invalid_grant unless family.person_id == person.id && family.application_id == client.id
          if parent.consumed_at
            revoke_family!(family, "replay_revoked", source.id)
            next :invalid_grant
          end
          next :invalid_grant if family.revoked_at || source.revoked?
        end

        response = yield
        next response unless response.is_a?(Doorkeeper::OAuth::TokenResponse)

        token = response.token
        raise "Issued token ownership mismatch" unless token.resource_owner_id == person.id && token.application_id == client.id
        family ||= TokenFamily.create!(person_id: person.id, application_id: client.id)
        parent&.update!(consumed_at: Time.now.utc)
        FamilyMember.create!(family_id: family.id, token_id: token.id, parent_id: parent&.id)
        LifecycleEvent.create!(person_id: person.id, family_id: family.id, token_id: token.id,
                               action: parent ? "rotated" : "issued")
        response
      end
    end

    def revoke_family!(family, action, token_id = nil)
      return if family.revoked_at

      now = Time.now.utc
      family.update!(revoked_at: now)
      token_ids = FamilyMember.where(family_id: family.id).select(:token_id)
      Doorkeeper::AccessToken.where(id: token_ids, revoked_at: nil).update_all(revoked_at: now)
      LifecycleEvent.create!(person_id: family.person_id, family_id: family.id, token_id: token_id, action: action)
    end

    def disable_person!
      with_person do |person|
        person.update!(enabled: false)
        TokenFamily.where(person_id: person.id, revoked_at: nil).order(:id).each do |family|
          revoke_family!(family, "disabled")
        end
        Doorkeeper::AccessToken.where(resource_owner_id: person.id, revoked_at: nil).update_all(revoked_at: Time.now.utc)
        Doorkeeper::AccessGrant.where(resource_owner_id: person.id, revoked_at: nil).update_all(revoked_at: Time.now.utc)
        Doorkeeper::DeviceAuthorizationGrant::DeviceGrant.where(resource_owner_id: person.id).delete_all
        LifecycleEvent.create!(person_id: person.id, action: "person_disabled")
      end
    end
  end
end
