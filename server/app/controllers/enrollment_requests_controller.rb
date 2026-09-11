# frozen_string_literal: true

# P3-a administrator enrollment review (plan §7.2 step 2-4, §21): the
# trusted-browser approval surface. Identity admins review pending device
# enrollment requests — hardware identity, key-possession status — and bind
# an acceptance to a person (§7.2 step 4). Owner or identity_admin only.
class EnrollmentRequestsController < ApplicationController
  include AdminRequired

  PER_PAGE = 10

  before_action :set_request, only: %i[accept reject destroy]

  def index
    scope = EnrollmentRequest.includes(:device)
    scope = scope.where(
      <<~SQL.squish,
        state ILIKE :term OR device_name ILIKE :term OR requested_device_id ILIKE :term OR
        machine_id ILIKE :term OR serial_number ILIKE :term OR manufacturer ILIKE :term OR
        model ILIKE :term OR public_key_hex ILIKE :term
      SQL
      term: "%#{EnrollmentRequest.sanitize_sql_like(params[:search].to_s)}%"
    ) if search?
    scope = scope.order(Arel.sql("CASE state WHEN 'pending' THEN 0 ELSE 1 END"), created_at: :desc)
    total_count = scope.count
    page = [ params.fetch(:page, 1).to_i, 1 ].max
    requests = scope.offset((page - 1) * PER_PAGE).limit(PER_PAGE)

    render Views::EnrollmentRequests::Index.new(
      requests:,
      people: Person.order(:display_name).includes(:login_aliases),
      search: params[:search].to_s,
      page:,
      per_page: PER_PAGE,
      total_count:
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

  def search?
    params[:search].present?
  end

  def find_person(email)
    Person.joins(:login_aliases).find_by(login_aliases: { email_address: email.strip.downcase })
  end

  def set_request
    @enrollment_request = EnrollmentRequest.find(params[:id])
  end
end
