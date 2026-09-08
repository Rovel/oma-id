class SessionsController < ApplicationController
  allow_unauthenticated_access only: %i[new create]
  # §5.1: rate limit credential attempts (Rails 8 rate_limit; per-IP).
  rate_limit to: 10, within: 3.minutes, only: :create,
             with: -> { redirect_to new_session_path, alert: "Try again later." }

  def new
    render Views::Sessions::New.new, layout: "application"
  end

  def create
    person = Person.authenticate_by_alias(
      email_address: params[:email_address].to_s,
      password: params[:password].to_s
    )
    if person
      start_new_session_for person
      AuditEvent.record!(actor: person.primary_email.to_s, action: "session.create", target: person.display_name, result: "success")
      redirect_to after_authentication_url
    else
      # §16: record the failure without revealing whether the alias exists.
      AuditEvent.record!(actor: "anonymous", action: "session.create", target: params[:email_address].to_s, result: "failure")
      redirect_to new_session_path, alert: "Try another email address or password."
    end
  end

  def destroy
    person_email = Current.person&.primary_email
    terminate_session
    AuditEvent.record!(actor: person_email.to_s, action: "session.destroy", result: "success")
    redirect_to new_session_path, status: :see_other
  end
end
