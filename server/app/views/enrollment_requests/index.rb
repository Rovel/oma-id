# frozen_string_literal: true

module Views
  module EnrollmentRequests
    # P3-a administrator enrollment review (plan §7.2 steps 2-4): pending
    # device requests with their hardware identity and key-possession status,
    # an accept form binding the device to a person (§7.2 step 4), and the
    # resolved history in a searchable, paginated DataTable.
    class Index < Views::Base
      include Phlex::Rails::Helpers::Routes

      def initialize(requests:, people:, search:, page:, per_page:, total_count:)
        @requests = requests
        @people = people
        @search = search
        @page = page
        @per_page = per_page
        @total_count = total_count
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

          render RubyUI::DataTable.new(id: "enrollment-requests") do
            render RubyUI::DataTableToolbar.new do
              render RubyUI::DataTableSearch.new(
                path: enrollment_requests_path,
                value: @search,
                placeholder: "Search device, hardware, key, or state…"
              )
            end

            div(class: "rounded-md border overflow-x-auto") do
              data_table_markup do
                thead(class: "[&_tr]:border-b") do
                  table_row do
                    table_head(class: "w-10") { "" }
                    table_head { "Device" }
                    table_head { "State" }
                    table_head { "Key possession" }
                    table_head { "Hardware" }
                    table_head { "Posted" }
                    table_head { "Outcome" }
                  end
                end
                tbody(class: "[&_tr:last-child]:border-0") do
                  empty_row if @requests.empty?
                  @requests.each { |request| request_rows(request) }
                end
              end
            end

            render RubyUI::DataTablePaginationBar.new do
              div(class: "text-sm text-muted-foreground") do
                plain "Showing #{@requests.size} of #{@total_count} request(s)."
              end
              render RubyUI::DataTablePagination.new(
                page: @page,
                per_page: @per_page,
                total_count: @total_count,
                path: enrollment_requests_path,
                query: { search: @search }
              )
            end
          end
        end
      end

      private

      def empty_row
        table_row do
          table_cell(colspan: 7) do
            p(class: "p-4 text-sm text-muted-foreground") do
              if @search.present?
                plain "No enrollment requests match."
              else
                plain "No enrollment requests yet. A device posts one on first contact with the server."
              end
            end
          end
        end
      end

      def request_rows(request)
        detail_id = "enrollment-request-#{request.id}-details"

        table_row do
          table_cell do
            render RubyUI::DataTableExpandToggle.new(
              controls: detail_id,
              label: "Show details for request #{request.id}",
              title: "Show request details"
            )
          end
          table_cell(class: "font-medium") do
            div { request.device_name.presence || "Unnamed device" }
            div(class: "text-xs text-muted-foreground") { "Request ##{request.id}" }
          end
          table_cell do
            render RubyUI::Badge.new(variant: state_variant(request), size: :sm) { request.state }
          end
          table_cell do
            render RubyUI::Badge.new(
              variant: request.key_possession_verified? ? :success : :warning,
              size: :sm
            ) do
              request.key_possession_verified? ? "Verified" : "Not verified"
            end
          end
          table_cell(class: "text-sm") do
            plain hardware_name(request)
          end
          table_cell(class: "text-sm text-muted-foreground whitespace-nowrap") do
            request.created_at.strftime("%Y-%m-%d %H:%M")
          end
          table_cell(class: "text-sm") { outcome(request) }
        end

        table_row(id: detail_id, class: "hidden bg-muted/20 hover:bg-muted/20") do
          table_cell(colspan: 7, class: "p-4") do
            dl(class: "grid gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-3") do
              detail("Manufacturer / model") { hardware_name(request) }
              detail("Serial number") { code { request.serial_number.presence || "unknown" } }
              detail("Machine ID") { code { request.machine_id.presence || "unknown" } }
              detail("Public key") { code { "#{request.public_key_hex[0, 32]}…" } }
              detail("Requested device id") { code { request.requested_device_id.presence || "none" } }
              detail("Key-possession proof") do
                if request.key_possession_verified?
                  plain "Verified #{request.key_possession_verified_at.strftime('%Y-%m-%d %H:%M')}"
                else
                  plain "Not verified — the device must poll its status"
                end
              end
              if request.device
                detail("Enrolled device") { code { request.device.device_id } }
              end
            end

            div(class: "mt-4") do
              if request.pending?
                accept_form(request)
                reject_form(request)
              elsif request.state != "accepted"
                clear_form(request)
              else
                p(class: "text-sm text-muted-foreground") { "This request has been accepted." }
              end
            end
          end
        end
      end

      def detail(label)
        div do
          dt(class: "text-xs font-medium text-muted-foreground") { label }
          dd(class: "mt-1 text-sm break-all") { yield }
        end
      end

      def hardware_name(request)
        [ request.manufacturer, request.model ].compact_blank.join(" · ").presence || "Unknown"
      end

      def state_variant(request)
        { "pending" => :warning, "accepted" => :success, "rejected" => :destructive }.fetch(request.state, :outline)
      end

      def outcome(request)
        return request.device.device_id if request.device
        return "Awaiting review" if request.pending?

        "Not enrolled"
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
