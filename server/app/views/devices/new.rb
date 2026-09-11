# frozen_string_literal: true

module Views
  module Devices
    # Technician pre-provisioning (§6.3): register a device key out of band.
    # Shares OmaId::EnrollDevice with the P3-a acceptance flow; the §8.4
    # POSIX mapping is allocated on the device's person if not present.
    class New < Views::Base
      include Phlex::Rails::Helpers::Routes

      def initialize(people: [])
        @people = people
        super()
      end

      def view_template
        div(class: "oma-container") do
          admin_header("Register device (technician)")

          render RubyUI::Card.new(class: "oma-card") do
            render RubyUI::CardHeader.new(class: "oma-card-header") do
              render RubyUI::CardTitle.new { "Device key registration" }
              render RubyUI::CardDescription.new do
                "Paste the device public key (64 hex chars) from the machine. " \
                  "The normal path is self-enrollment; this form is the §6.3 technician path."
              end
            end
            render RubyUI::CardContent.new(class: "oma-card-content") do
              form(action: devices_path, method: "post", class: "oma-form") do
                input(type: "hidden", name: "authenticity_token", value: form_authenticity_token)
                label { "Person (login alias)" }
                select(name: "person_email", required: true, class: "oma-input") do
                  option(value: "", disabled: true, selected: true) { "Choose a person…" }
                  @people.each do |person|
                    option(value: person.primary_email) { "#{person.display_name} <#{person.primary_email}>" }
                  end
                end
                label { "Device id" }
                input(type: "text", name: "device_id", required: true, placeholder: "workstation-1",
                      pattern: "[a-z0-9][a-z0-9-]*", class: "oma-input")
                label { "Device public key (64 hex chars)" }
                input(type: "text", name: "public_key_hex", required: true, minlength: 64,
                      maxlength: 64, class: "oma-input font-mono")
                render RubyUI::Button.new(type: "submit", class: "mt-3") { "Register device" }
              end
            end
          end
        end
      end
    end
  end
end
