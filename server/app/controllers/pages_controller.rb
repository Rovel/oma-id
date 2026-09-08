# Renders the P1-a identity front. Authentication is required (the
# ApplicationController concern enforces it); the page shows the verified
# organization confirmation (plan §6.2) and the signed-in person's identity.
class PagesController < ApplicationController
  # The organization confirmation surface is public display information
  # (plan §6.2/§11.4 — the burnt-PC selector and §6.2 comparison rely on it);
  # it also renders a signed-in banner when a session exists.
  allow_unauthenticated_access only: :home

  def home
    @organization = Organization.first
    render Views::Pages::Home.new(organization: @organization), layout: "application"
  end
end
