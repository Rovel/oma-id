# frozen_string_literal: true

# P3-a administrator enrollment review (plan §7.2 step 2-4, §21): the
# trusted-browser approval surface. Identity admins review pending device
# enrollment requests — hardware identity, key-possession status — and bind
# an acceptance to a person (§7.2 step 4). Owner or identity_admin only.
class EnrollmentRequestsController < ApplicationController
  include AdminRequired

  before_action :set_request, only: %i[accept reject destroy]

  def index
    render Views::EnrollmentRequests::Index.new(
      pending: EnrollmentRequest.pending.recent_first,
      resolved: EnrollmentRequest.where.not(state: "pending").recent_first.limit(50),
      people: Person.order(:display_name).includes(:login_aliases)
    ), layout: "application"
  end

  def accept
    person = find_person(params[:person_email].to_s)
    device_id = params[:device_id].to_s.strip.downcase
    if person.nil? || device_id.blank?
      redirect_to enrollment_requests_path, alert: "Choose a person and a device id to accept."
      return
    end

    begin
      device = @enrollment_request.accept!(person:, device_id:, actor: actor_name)
      redirect_to enrollment_requests_path,
                  notice: "Device #{device.device_id} enrolled for #{person.primary_email} (POSIX mapping allocated)."
    rescue EnrollmentRequest::NotReady, OmaId::EnrollDevice::EnrollError => e
      redirect_to enrollment_requests_path, alert: "Enrollment refused: #{e.message}"
    end
  end

  def reject
    @enrollment_request.reject!(actor: actor_name)
    redirect_to enrollment_requests_path, notice: "Enrollment request rejected."
  rescue EnrollmentRequest::NotReady => e
    redirect_to enrollment_requests_path, alert: "Refused: #{e.message}"
  end

  # Re-enrollment for a rejected/accepted key needs a fresh lifecycle (§7.3):
  # the administrator clears the old request and the device posts a new one.
  def destroy
    @enrollment_request.destroy!
    AuditEvent.record!(actor: actor_name, action: "enrollment.clear",
                       target: "enrollment_request:#{@enrollment_request.id}", result: "success")
    redirect_to enrollment_requests_path, notice: "Enrollment request cleared; the device can post a new one."
  end

  private

  def find_person(email)
    Person.joins(:login_aliases).find_by(login_aliases: { email_address: email.strip.downcase })
  end

  def set_request
    @enrollment_request = EnrollmentRequest.find(params[:id])
  end
end
