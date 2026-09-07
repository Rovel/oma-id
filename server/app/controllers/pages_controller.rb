# Renders the P0 identity front. No authentication yet: this slice is the
# organization display surface (plan §6.2: verified organization name,
# support contact, and management scope — "a logo alone proves nothing")
# plus lab-scope honesty. People/admin login is P1 work.
class PagesController < ApplicationController
  def home
    @organization = Organization.first
    render Views::Pages::Home.new(organization: @organization), layout: "application"
  end
end
