# frozen_string_literal: true

module Lab
  # P0 composition adapter for the pinned extensions, not an upstream gem patch.
  class DiscoveryController < Doorkeeper::OpenidConnect::DiscoveryController
    private

    def provider_response
      response = super
      return response unless Doorkeeper.configuration.grant_flows.include?("device_code")

      response.merge(
        grant_types_supported: response.fetch(:grant_types_supported).map do |grant|
          grant == "device_code" ? "urn:ietf:params:oauth:grant-type:device_code" : grant
        end,
        device_authorization_endpoint: "#{Lab::ISSUER}/oauth/authorize_device",
      )
    end
  end
end
