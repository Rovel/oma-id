# frozen_string_literal: true

module Views
  module People
    # Add a person (plan §5.1): display name, role, primary login alias,
    # optional password (generated + shown once when omitted — §10: local).
    class New < Views::Base
      include Phlex::Rails::Helpers::Routes

      def initialize(person:)
        @person = person
        super()
      end

      def view_template
        div(class: "oma-container") do
          admin_header("Add person")

          render RubyUI::Card.new(class: "oma-card") do
            render RubyUI::CardContent.new(class: "oma-card-content") do
              form(action: people_path, method: "post", class: "oma-form") do
                input(type: "hidden", name: "authenticity_token", value: form_authenticity_token)
                label { "Display name" }
                input(type: "text", name: "display_name", required: true, class: "oma-input")
                label { "Email (primary login alias)" }
                input(type: "email", name: "email_address", required: true, class: "oma-input")
                label { "Role" }
                select(name: "role", class: "oma-input") do
                  option(value: "employee") { "employee" }
                  option(value: "identity_admin") { "identity_admin" }
                  option(value: "owner") { "owner" }
                end
                label { "Password (leave blank to generate one, shown once)" }
                input(type: "password", name: "password", autocomplete: "new-password", class: "oma-input")
                render RubyUI::Button.new(type: "submit", class: "mt-3") { "Create person" }
              end
            end
          end
        end
      end
    end
  end
end
