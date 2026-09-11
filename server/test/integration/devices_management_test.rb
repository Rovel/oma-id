# frozen_string_literal: true

require "test_helper"

# Admin fleet management (plan §7/§7.3): device DataTable, technician
# registration through the shared OmaId::EnrollDevice path, removal stops
# check-in authorization, role gating.
class DevicesManagementTest < ActionDispatch::IntegrationTest
  setup do
    @admin = Person.create!(
      display_name: "Ada Admin", role: :identity_admin,
      password: "correct-horse", password_confirmation: "correct-horse"
    )
    @admin.login_aliases.create!(email_address: "ada@lab.test")
    sign_in_as(@admin, password: "correct-horse")
  end

  test "admin registers a device out-of-band (technician §6.3 path)" do
    post devices_path, params: { person_email: "ada@lab.test", device_id: "tech-reg-1",
                                 public_key_hex: "a" * 64 }
    assert_redirected_to devices_path
    device = Device.find_by(device_id: "tech-reg-1")
    assert device&.active?
    assert_equal @admin.id, device.person_id
    assert AuditEvent.where(action: "device.register", target: "tech-reg-1").exists?
  end

  test "technician registration reuses the §8.4 mapping allocation" do
    post devices_path, params: { person_email: "ada@lab.test", device_id: "tech-reg-2",
                                 public_key_hex: "b" * 64 }
    mapping = PosixIdentityMapping.find_by(person: @admin)
    assert mapping, "POSIX mapping allocated for the device's person"
  end

  test "malformed keys are refused with the shared error" do
    post devices_path, params: { person_email: "ada@lab.test", device_id: "tech-bad",
                                 public_key_hex: "zz" }
    assert_redirected_to new_device_path
    assert_not Device.exists?(device_id: "tech-bad")
  end

  test "device removal deletes the row, keeps the mapping, and audits" do
    device = @admin.devices.create!(device_id: "remove-me", public_key_hex: "c" * 64, state: "active")
    PosixIdentityMapping.create!(person: @admin, username: "ada", uid: 10_001, gid: 10_001,
                                 home: "/home/ada", shell: "/bin/zsh", full_name: "Ada")

    delete device_path(device)
    assert_redirected_to devices_path
    assert_not Device.exists?(device.id)
    assert PosixIdentityMapping.exists?(username: "ada"), "the mapping stays with the person"
    assert AuditEvent.where(action: "device.remove", target: "remove-me").exists?
  end

  test "employee role cannot reach the devices surface" do
    employee = Person.create!(display_name: "Emp2", role: :employee,
                              password: "x" * 12, password_confirmation: "x" * 12)
    employee.login_aliases.create!(email_address: "emp2@lab.test")
    sign_in_as(employee, password: "x" * 12)

    get devices_path
    assert_redirected_to root_path
  end
end
