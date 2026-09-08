# frozen_string_literal: true

module Views
  module Sessions
    # P1-a sign-in form (§5.1 password fallback). Passwords are the P1-a
    # boundary: passkeys (WebAuthn) are the preferred method and arrive in
    # P1-b. Rate limiting is enforced controller-side (§5.1).
    class New < Views::Base
      def view_template
        div(class: "oma-container") do
          header(class: "oma-header") do
            render RubyUI::Badge.new(class: "oma-badge") { "OMA-ID" }
            h1 { "Sign in" }
          end

          render RubyUI::Card.new(class: "oma-card") do
            render RubyUI::CardContent.new(class: "oma-card-content") do
              form(action: session_path, method: "post", class: "oma-form") do
                input(type: "hidden", name: "authenticity_token", value: form_authenticity_token)
                label(for: "email_address") { "Email address" }
                input(type: "email", name: "email_address", id: "email_address",
                      required: true, autofocus: true, autocomplete: "username")

                label(for: "password") { "Password" }
                input(type: "password", name: "password", id: "password",
                      required: true, autocomplete: "current-password")

                button(type: "submit") { "Sign in" }
              end
            end
          end

          p(class: "oma-endpoint") do
            plain "Password authentication is the P1-a fallback credential; "
            plain "passkeys arrive with P1-b."
          end
        end
      end
    end
  end
end
