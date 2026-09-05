# frozen_string_literal: true

# This checks library loading/rendering only, not OAuth or application behavior.
require "rails"
require "active_record"
require "action_controller/railtie"
Bundler.require

class DependencySmokeView < Phlex::HTML
  def view_template
    p { "OMA-ID <local development>" }
  end
end

expected = "<p>OMA-ID &lt;local development&gt;</p>"
raise "Unexpected Phlex output" unless DependencySmokeView.new.call == expected

puts "Ruby #{RUBY_VERSION}; Rails #{Rails.version}; selected dependencies loaded; Phlex rendering passed."
