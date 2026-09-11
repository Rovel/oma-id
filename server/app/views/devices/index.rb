# frozen_string_literal: true

module Views
  module Devices
    # Administrator fleet view (plan §7): the RubyUI DataTable over managed
    # devices — search, pagination — with enrollment state, last check-in,
    # and removal (§7.3: removal stops check-in authorization immediately).
    class Index < Views::Base
      include Phlex::Rails::Helpers::Routes

      def initialize(devices:, search:, page:, per_page:, total_count:)
        @devices = devices
        @search = search
        @page = page
        @per_page = per_page
        @total_count = total_count
        super()
      end

      def view_template
        div(class: "oma-container oma-admin") do
          admin_header("Devices")

          render RubyUI::DataTable.new(id: "devices") do
            render RubyUI::DataTableToolbar.new do
              render RubyUI::DataTableSearch.new(path: devices_path, value: @search,
                                                 placeholder: "Search device id…")
            end

            div(class: "rounded-md border overflow-x-auto") do
              data_table_markup do
                thead(class: "[&_tr]:border-b") do
                  table_row do
                    table_head { "Device id" }
                    table_head { "State" }
                    table_head { "Person" }
                    table_head { "Key" }
                    table_head { "Last check-in" }
                    table_head(class: "text-right") { "Actions" }
                  end
                end
                tbody(class: "[&_tr:last-child]:border-0") do
                  if @devices.empty?
                    table_row do
                      table_cell(colspan: 6) do
                        p(class: "p-4 text-sm text-muted-foreground") { "No devices match." }
                      end
                    end
                  end
                  @devices.each do |device|
                    table_row do
                      table_cell(class: "font-medium") { code { device.device_id } }
                      table_cell do
                        render RubyUI::Badge.new(variant: device.active? ? :default : :destructive) do
                          device.state
                        end
                      end
                      table_cell { code { device.person.primary_email.to_s } }
                      table_cell { code { "#{device.public_key_hex[0, 12]}…" } }
                      table_cell(class: "text-sm text-muted-foreground") do
                        device.last_check_in_at ? device.last_check_in_at.strftime("%Y-%m-%d %H:%M") : "never"
                      end
                      table_cell(class: "text-right") do
                        form(action: device_path(device), method: "post", class: "inline") do
                          input(type: "hidden", name: "_method", value: "delete")
                          input(type: "hidden", name: "authenticity_token", value: form_authenticity_token)
                          render RubyUI::Button.new(variant: :destructive, size: :sm, type: "submit") { "Remove" }
                        end
                      end
                    end
                  end
                end
              end
            end

            render RubyUI::DataTablePaginationBar.new do
              render RubyUI::DataTableSelectionSummary.new(total_on_page: @devices.size)
              render RubyUI::DataTablePagination.new(page: @page, per_page: @per_page,
                                                     total_count: @total_count, path: devices_path)
            end
          end

          div(class: "mt-4") do
            a(href: new_device_path) do
              render RubyUI::Button.new(variant: :default, size: :sm) { "Register device (technician)" }
            end
          end
        end
      end
    end
  end
end
