# frozen_string_literal: true

module Views
  module EnrollmentRequests
    # P3-a administrator enrollment review (plan §7.2 steps 2-4): pending
    # device requests with their hardware identity and key-possession status,
    # an accept form binding the device to a person (§7.2 step 4), and the
    # resolved history. Shows exactly what the administrator needs to judge
    # the request — nothing more.
    class Index < Views::Base
      include Phlex::Rails::Helpers::Routes

      def initialize(pending:, resolved:, people:)
        @pending = pending
        @resolved = resolved
        @people = people
        @person = Current.person
        super()
      end

      def view_template
        div(class: "oma-container oma-admin") do
          admin_header("Enrollment requests")

          p(class: "oma-endpoint") do
            plain "A pending request has no organizational access (plan §7.3). Acceptance requires a "
            plain "device-signed status poll first (key-possession proof, §7.2 step 4)."
          end

          unless @pending.empty?
            h2 { "Pending" }
            @pending.each { |request| request_card(request, pending: true) }
          end

          unless @resolved.empty?
            h2 { "Resolved" }
            @resolved.each { |request| request_card(request, pending: false) }
          end

          if @pending.empty? && @resolved.empty?
            render RubyUI::Card.new(class: "oma-card") do
              render RubyUI::CardContent.new(class: "oma-card-content") do
                p { "No enrollment requests yet. A device posts one on first contact with the server." }
              end
            end
          end
        end
      end

      private

      def request_card(request, pending:)
        render RubyUI::Card.new(class: "oma-card") do
          render RubyUI::CardHeader.new(class: "oma-card-header") do
            render RubyUI::CardTitle.new { request.device_name || "Unnamed device" }
            render RubyUI::CardDescription.new do
              plain "request ##{request.id} · #{request.state}"
              if request.key_possession_verified?
                plain " · key possession VERIFIED #{request.key_possession_verified_at.strftime('%Y-%m-%d %H:%M')}"
              else
                plain " · key possession NOT verified (device must poll its status)"
              end
            end
          end
          render RubyUI::CardContent.new(class: "oma-card-content") do
            dl(class: "oma-facts") do
              dt { "Manufacturer / model" }
              dd { [request.manufacturer, request.model].compact.join(" · ").presence || "unknown" }
              dt { "Serial number" }
              dd { code { request.serial_number || "unknown" } }
              dt { "Machine ID" }
              dd { code { request.machine_id || "unknown" } }
              dt { "Public key" }
              dd { code { "#{request.public_key_hex[0, 32]}…" } }
              dt { "Requested device id" }
              dd { code { request.requested_device_id || "none" } }
              dt { "Posted" }
              dd { request.created_at.strftime("%Y-%m-%d %H:%M") }
              if request.device
                dt { "Enrolled device" }
                dd { code { request.device.device_id } }
              end
            end

            if pending
              accept_form(request)
              reject_form(request)
            elsif request.state != "accepted"
              clear_form(request)
            end
          end
        end
      end

      def accept_form(request)
        form(action: accept_enrollment_request_path(request), method: "post", class: "oma-inline-form") do
          input(type: "hidden", name: "authenticity_token", value: form_authenticity_token)
          # §7.2 step 2: the administrator reviews and binds the device to a
          # person. The combobox lists every person's primary alias — no
          # email memorization, no typo surface.
          div(class: "oma-combobox-slot") do
            render RubyUI::Combobox.new(class: "w-64") do
              render RubyUI::ComboboxInputTrigger.new(placeholder: "Choose person…")
              render RubyUI::ComboboxPopover.new do
                render RubyUI::ComboboxList.new do
                  render RubyUI::ComboboxEmptyState.new { "No person matches." }
                  @people.each do |person|
                    render RubyUI::ComboboxItem.new do
                      render RubyUI::ComboboxRadio.new(name: "person_email", value: person.primary_email)
                      span { "#{person.display_name} <#{person.primary_email}>" }
                    end
                  end
                end
              end
            end
          end
          input(type: "text", name: "device_id", value: request.requested_device_id || "",
                placeholder: "device id", required: true, class: "oma-input")
          render RubyUI::Button.new(type: "submit", class: "oma-accept") { "Accept" }
        end
      end

      def reject_form(request)
        form(action: reject_enrollment_request_path(request), method: "post", class: "oma-inline-form") do
          input(type: "hidden", name: "authenticity_token", value: form_authenticity_token)
          render RubyUI::Button.new(variant: :destructive, type: "submit") { "Reject" }
        end
      end

      def clear_form(request)
        form(action: enrollment_request_path(request), method: "post", class: "oma-inline-form") do
          input(type: "hidden", name: "_method", value: "delete")
          input(type: "hidden", name: "authenticity_token", value: form_authenticity_token)
          render RubyUI::Button.new(variant: :outline, type: "submit") { "Clear (allows a new request)" }
        end
      end
    end
  end
end
