# frozen_string_literal: true

module Views
  module People
    # The one-time password display (§10, bootstrap discipline): rendered
    # once from freshly generated material, never persisted outside its
    # bcrypt digest, never logged, never stored in a session or flash.
    class PasswordReset < Views::Base
      include Phlex::Rails::Helpers::Routes

      def initialize(person:, password:, action_label:)
        @person = person
        @password = password
        @action_label = action_label
        super()
      end

      def view_template
        div(class: "oma-container") do
          admin_header("Password #{@action_label}")

          render RubyUI::Card.new(class: "oma-card") do
            render RubyUI::CardHeader.new(class: "oma-card-header") do
              render RubyUI::CardTitle.new do
                "New password for #{@person.display_name} (#{@person.primary_email})"
              end
              render RubyUI::CardDescription.new do
                plain "Copy it now — it is shown "
                strong { "only this once" }
                plain ". It is stored only as a bcrypt digest and never synced anywhere (plan §10)."
              end
            end
            render RubyUI::CardContent.new(class: "oma-card-content") do
              p do
                code(class: "oma-password") { @password }
              end
              div(class: "mt-3") do
                a(href: people_path) do
                  render RubyUI::Button.new(variant: :outline, size: :sm) { "Back to people" }
                end
              end
            end
          end
        end
      end
    end
  end
end
