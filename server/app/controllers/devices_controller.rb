# frozen_string_literal: true

# Administrator device management (plan §7): review the fleet, register a
# device out-of-band (the §6.3 technician path, sharing OmaId::EnrollDevice
# with the P3-a acceptance flow), or remove a device. Removal is §7.3
# "revoked" in spirit: the device's check-ins immediately stop authorizing
# (opaque 401), its issued leases age out per §9.2, and the action is
# audited. The provisioned POSIX mapping stays with the person (the local
# account remains on the machine).
class DevicesController < ApplicationController
  include AdminRequired

  PER_PAGE = 10

  before_action :set_device, only: %i[destroy]

  def index
    scope = Device.order(:created_at).includes(:person)
    scope = scope.where("device_id LIKE ?", "%#{Device.sanitize_sql_like(params[:search].to_s)}%") if search?
    @total_count = scope.count
    @page = params[:page].to_i
    @per_page = PER_PAGE
    @devices = scope.offset((@page - 1) * @per_page).limit(@per_page)
    render Views::Devices::Index.new(devices: @devices, search: params[:search].to_s,
                                     page: @page, per_page: @per_page, total_count: @total_count),
           layout: "application"
  end

  def new
    render Views::Devices::New.new(people: Person.order(:display_name).includes(:login_aliases)),
           layout: "application"
  end

  # Technician pre-provisioning (§6.3): bind a device key to a person out
  # of band. Shares OmaId::EnrollDevice with the P3-a acceptance flow, so
  # both paths provision identically (device + §8.4 POSIX mapping).
  def create
    person = Person.joins(:login_aliases).find_by(login_aliases: { email_address: params[:person_email].to_s })
    raise ActiveRecord::RecordNotFound unless person

    device = OmaId::EnrollDevice.call!(person:, device_id: params[:device_id].to_s,
                                      public_key_hex: params[:public_key_hex].to_s)
    mapping = PosixIdentityMapping.find_by(person:)
    AuditEvent.record!(actor: actor_name, action: "device.register", target: device.device_id,
                       result: "success",
                       metadata: { person_email: person.primary_email, posix_username: mapping&.username })
    redirect_to devices_path, notice: "Device #{device.device_id} registered (state=active)."
  rescue OmaId::EnrollDevice::EnrollError => e
    redirect_to new_device_path, alert: "Refused: #{e.message}"
  end

  def destroy
    ActiveRecord::Base.transaction do
      @device.destroy!
      AuditEvent.record!(actor: actor_name, action: "device.remove", target: @device.device_id,
                         result: "success", metadata: { note: "check-ins now fail closed (opaque 401); issued leases age out (§9.2)" })
    end
    redirect_to devices_path, notice: "Device #{@device.device_id} removed; its check-ins now fail closed."
  end

  private

  def set_device
    @device = Device.find(params[:id])
  end

  def search?
    params[:search].present?
  end
end
