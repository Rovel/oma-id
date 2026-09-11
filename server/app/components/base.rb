# frozen_string_literal: true

# Shared admin chrome for the managed-directory pages (plan §21): title,
# role banner, and navigation between the admin surfaces.
module Components
  module AdminChrome
    def admin_header(title)
      header(class: "oma-header") do
        a(href: root_path) do
          render RubyUI::Badge.new(class: "oma-badge w-full") { "OMA-ID" }
        end
        h1 { title }
        if (person = Current.person)
          span(class: "oma-person") { plain "#{person.display_name} (#{person.role})" }
        end
        nav(class: "oma-admin-nav") do
          admin_nav_link("People", people_path)
          admin_nav_link("Devices", devices_path)
          admin_nav_link("Enrollment", enrollment_requests_path)
        end
        a(href: root_path, class: "oma-signout") { "Front" }
      end
    end

    private

    def admin_nav_link(label, path)
      active = helpers.request.path == path
      a(href: path, class: active ? "oma-admin-nav-link active" : "oma-admin-nav-link") { label }
    end
  end
end

class Components::Base < Phlex::HTML
  include RubyUI
  include Components::AdminChrome
  # Include any helpers you want to be available across all components
  include Phlex::Rails::Helpers::Routes
  include Phlex::Rails::Helpers::FormAuthenticityToken

  if Rails.env.development?
    def before_template
      comment { "Before #{self.class.name}" }
      super
    end
  end
end
