# frozen_string_literal: true

module Views
  module People
    # Administrator directory (plan §21): the RubyUI DataTable over people —
    # server-side search, sort, pagination — plus create and removal (§5.1:
    # aliases bind people; removal refuses while devices are enrolled).
    class Index < Views::Base
      include Phlex::Rails::Helpers::Routes

      def initialize(people:, search:, page:, per_page:, total_count:)
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
          admin_header("People")

          render RubyUI::DataTable.new(id: "people") do
            render RubyUI::DataTableToolbar.new do
              render RubyUI::DataTableSearch.new(path: people_path, value: @search,
                                                 placeholder: "Search name or email…")
            end

            div(class: "rounded-md border overflow-x-auto") do
              render RubyUI::Table.new do
                render RubyUI::TableHeader do
                  render RubyUI::TableRow do
                    render RubyUI::TableHead { "Added" }
                    render RubyUI::TableHead { "Name" }
                    render RubyUI::TableHead { "Email (login alias)" }
                    render RubyUI::TableHead { "Role" }
                    render RubyUI::TableHead { "Devices" }
                    render RubyUI::TableHead(class: "text-right") { "Actions" }
                  end
                end
                render RubyUI::TableBody do
                  if @people.empty?
                    render RubyUI::TableRow do
                      render RubyUI::TableCell(colspan: 6) do
                        p(class: "p-4 text-sm text-muted-foreground") { "No people match." }
                      end
                    end
                  end
                  @people.each do |person|
                    render RubyUI::TableRow do
                      render RubyUI::TableCell(class: "text-sm text-muted-foreground") do
                        person.created_at.strftime("%Y-%m-%d")
                      end
                      render RubyUI::TableCell(class: "font-medium") { person.display_name }
                      render RubyUI::TableCell { code { person.primary_email.to_s } }
                      render RubyUI::TableCell do
                        render RubyUI::Badge.new(variant: person.role == "employee" ? :secondary : :outline) do
                          person.role
                        end
                      end
                      render RubyUI::TableCell(class: "text-sm") { person.devices.count.to_s }
                      render RubyUI::TableCell(class: "text-right space-x-2") do
                        form(action: reset_password_person_path(person), method: "post", class: "inline") do
                          input(type: "hidden", name: "authenticity_token", value: form_authenticity_token)
                          render RubyUI::Button.new(variant: :outline, size: :sm, type: "submit") { "Reset password" }
                        end
                        if person.devices.exists?
                          render RubyUI::Button.new(variant: :destructive, size: :sm,
                                                    disabled: true, title: "Remove enrolled devices first (§8.4)") do
                            "Remove"
                          end
                        else
                          form(action: person_path(person), method: "post", class: "inline") do
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
            end

            render RubyUI::DataTablePaginationBar.new do
              render RubyUI::DataTableSelectionSummary.new(total_on_page: @people.size)
              render RubyUI::DataTablePagination.new(page: @page, per_page: @per_page,
                                                     total_count: @total_count, path: people_path)
            end
          end

          div(class: "mt-4") do
            a(href: new_person_path) do
              render RubyUI::Button.new(variant: :default, size: :sm) { "Add person" }
            end
          end
        end
      end
    end
  end
end
