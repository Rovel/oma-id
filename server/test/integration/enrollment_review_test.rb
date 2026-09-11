# frozen_string_literal: true

require "test_helper"

# P3-a administrator enrollment review (plan §7.2 steps 2-4): the
# trusted-browser surface. Role-gated (owner/identity_admin only), acceptance
# binds the device to a person, and every action is audited (§16).
class EnrollmentReviewTest < ActionDispatch::IntegrationTest
  setup do
    @admin = Person.create!(
      display_name: "Ada Admin", role: :identity_admin,
      password: "correct-horse", password_confirmation: "correct-horse"
    )
    @admin.login_aliases.create!(email_address: "ada@lab.test")
    @employee = Person.create!(
      display_name: "Rustam Employee", role: :employee,
      password: "correct-horse", password_confirmation: "correct-horse"
    )
    @employee.login_aliases.create!(email_address: "rustam@lab.test")
    @key_hex = SecureRandom.bytes(32).unpack1("H*")
    sign_in_as(@admin, password: "correct-horse")
  end

  test "an admin sees the pending request with its device details" do
    EnrollmentRequest.record!(public_key_hex: @key_hex, device_name: "Burnt PC",
                              manufacturer: "ASUSTeK", model: "PRIME B550M-A",
                              serial_number: "SN123456", requested_device_id: "workstation-1")

    get enrollment_requests_path
    assert_response :ok
    assert_select "turbo-frame#enrollment-requests"
    assert_select "input[type=search][name=search]"
    assert_select "table tbody td form", minimum: 2
    assert_match "Burnt PC", response.body
    assert_match "PRIME B550M", response.body
    assert_match "Not verified", response.body
  end

  test "the enrollment table searches requests and normalizes invalid pages" do
    EnrollmentRequest.record!(public_key_hex: @key_hex, device_name: "Burnt PC", serial_number: "SN123456")
    EnrollmentRequest.record!(public_key_hex: SecureRandom.hex(32), device_name: "Other device")

    get enrollment_requests_path, params: { search: "SN123456" }
    assert_response :ok
    assert_match "Burnt PC", response.body
    assert_no_match "Other device", response.body

    get enrollment_requests_path, params: { page: -1 }
    assert_response :ok
    assert_match "Burnt PC", response.body
  end

  test "acceptance requires a person and a device id" do
    request_record = EnrollmentRequest.record!(public_key_hex: @key_hex, device_name: "box")
    request_record.mark_key_possession_verified!

    post accept_enrollment_request_path(request_record), params: { person_email: "", device_id: "" }
    assert_redirected_to enrollment_requests_path
    assert_equal "pending", request_record.reload.state
  end

  test "admin accepts: device becomes active with a POSIX mapping and an audit event" do
    request_record = EnrollmentRequest.record!(public_key_hex: @key_hex, device_name: "Burnt PC",
                                               requested_device_id: "workstation-1")
    request_record.mark_key_possession_verified!

    post accept_enrollment_request_path(request_record),
         params: { person_email: "rustam@lab.test", device_id: "workstation-1" }
    assert_redirected_to enrollment_requests_path

    device = Device.find_by(device_id: "workstation-1")
    assert device&.active?
    assert_equal @employee.id, device.person_id
    assert_equal "accepted", request_record.reload.state
    assert PosixIdentityMapping.find_by(person: @employee), "§8.4 mapping allocated"
    assert AuditEvent.where(action: "enrollment.accept").exists?
  end

  test "acceptance is refused while key possession is unverified" do
    request_record = EnrollmentRequest.record!(public_key_hex: @key_hex, device_name: "box")
    post accept_enrollment_request_path(request_record),
         params: { person_email: "rustam@lab.test", device_id: "workstation-1" }
    assert_redirected_to enrollment_requests_path
    assert_nil Device.find_by(device_id: "workstation-1"), "no device without the §7.2 step-4 proof"
    assert_equal "pending", request_record.reload.state
  end

  test "reject then clear lets the device post a fresh request (§7.3 lifecycle)" do
    request_record = EnrollmentRequest.record!(public_key_hex: @key_hex, device_name: "box")
    request_record.mark_key_possession_verified!

    post reject_enrollment_request_path(request_record)
    assert_equal "rejected", request_record.reload.state

    delete enrollment_request_path(request_record)
    assert_not EnrollmentRequest.exists?(request_record.id)

    fresh = EnrollmentRequest.record!(public_key_hex: @key_hex, device_name: "box")
    assert fresh.pending?
    assert_not_equal request_record.id, fresh.id
  end

  test "employee role cannot see the review surface" do
    sign_in_as(@employee, password: "correct-horse")
    get enrollment_requests_path
    assert_redirected_to root_path
  end
end
