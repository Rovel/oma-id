# frozen_string_literal: true

module Views
  module Pages
    # P0/P1 identity front. Server-rendered Phlex + RubyUI components
    # (ADR-001, docs/adr/0002). Shows exactly what plan §6.2 requires an
    # enrollment confirmation to show: organization identity, support
    # contact, and the canonical issuer — plus an honest lab scope notice.
    # P1-a: renders a signed-in banner (person + role + sign-out) when a
    # session exists.
    class Home < Views::Base
      include Phlex::Rails::Helpers::Routes

      def initialize(organization:)
        @organization = organization
        @person = Current.person
        super()
      end

      def view_template
        div(class: "oma-container") do
          header(class: "oma-header") do
            render RubyUI::Badge.new(class: "oma-badge") { "OMA-ID" }
            h1 { org_name }
            if @person
              span(class: "oma-person") do
                plain "#{@person.display_name} (#{@person.role})"
              end
              form(action: session_path, method: "post", class: "oma-inline-form") do
                input(type: "hidden", name: "_method", value: "delete")
                input(type: "hidden", name: "authenticity_token", value: form_authenticity_token)
                button(type: "submit", class: "oma-signout") { "Sign out" }
              end
            end
          end

          if @organization
            render RubyUI::Card.new(class: "oma-card") do
              render RubyUI::CardHeader.new(class: "oma-card-header") do
                render RubyUI::CardTitle.new { "Organization" }
                render RubyUI::CardDescription.new { "Verified server identity for enrollment confirmation" }
              end
              render RubyUI::CardContent.new(class: "oma-card-content") do
                dl(class: "oma-facts") do
                  dt { "Organization" }
                  dd { @organization.name }
                  dt { "Canonical issuer" }
                  dd { code { @organization.issuer } }
                  dt { "Support contact" }
                  dd { @organization.support_email }
                  dt { "Enrollment methods" }
                  dd { "None live on this server (P0 lab slice)" }
                end
              end
            end

            p(class: "oma-endpoint") do
              plain "Public metadata: "
              code { enrollment_metadata_url }
            end
          else
            render RubyUI::Card.new(class: "oma-card") do
              render RubyUI::CardContent.new(class: "oma-card-content") do
                h2 { "Organization not configured" }
                p do
                  plain "Run "
                  code { "bin/rails db:prepare" }
                  plain " to seed the lab organization."
                end
              end
            end
          end

          footer(class: "oma-footer") do
            plain "P0/P1 lab slice — fake identities, development-only data. "
            plain "No login or enrollment gate has passed on this server."
          end
        end
      end

      private

      def org_name
        @organization ? @organization.name : "OMA-ID"
      end
    end
  end
end
