# frozen_string_literal: true

require "test_helper"

# P3-a enrollment request lifecycle (plan §7.2, §7.3): pending → accepted
# (admin, key-proof-gated, bound to a person) / rejected; idempotent
# creation; POSIX mapping allocated on acceptance (§8.4).
class EnrollmentRequestTest < ActiveSupport::TestCase
  setup do
    @person = Person.create!(
      display_name: "Ada Admin",
      role: :identity_admin,
      password: "correct-horse",
      password_confirmation: "correct-horse"
    )
    @person.login_aliases.create!(email_address: "ada@lab.test")
    @key_hex = SecureRandom.bytes(32).unpack1("H*")
    @attrs = { public_key_hex: @key_hex, device_name: "Test Box", manufacturer: "ACME",
               model: "BX-1", serial_number: "SN1", machine_id: "abcd" * 8 }
  end

  test "record! creates a pending request and is idempotent per key" do
    first = EnrollmentRequest.record!(@attrs)
    assert first.pending?
    second = EnrollmentRequest.record!(@attrs.merge(device_name: "Renamed"))
    assert_equal first.id, second.id
    assert_equal "Renamed", second.device_name
    assert_equal 1, EnrollmentRequest.count
  end

  test "record! refreshes details but never flips state back to pending" do
    request_record = EnrollmentRequest.record!(@attrs)
    request_record.update!(state: "rejected")
    refreshed = EnrollmentRequest.record!(@attrs.merge(device_name: "Again"))
    assert_equal "rejected", refreshed.state
  end

  test "accept! is refused without key-possession proof (§7.2 step 4)" do
    request_record = EnrollmentRequest.record!(@attrs)
    error = assert_raises(EnrollmentRequest::NotReady) do
      request_record.accept!(person: @person, device_id: "workstation-1", actor: "test")
    end
    assert_match(/possession not verified/, error.message)
    assert_equal "pending", request_record.reload.state
  end

  test "accept! binds the device to a person, allocates the POSIX mapping, and audits" do
    request_record = EnrollmentRequest.record!(@attrs)
    request_record.mark_key_possession_verified!
    device = request_record.accept!(person: @person, device_id: "workstation-1", actor: "test")

    assert_equal "accepted", request_record.reload.state
    assert_equal device.id, request_record.device_id
    assert device.active?
    assert_equal @person.id, device.person_id
    mapping = PosixIdentityMapping.find_by(person: @person)
    assert mapping, "POSIX mapping allocated on acceptance (§8.4)"
    assert_equal "ada", mapping.username
  end

  test "accept! is refused once already resolved" do
    request_record = EnrollmentRequest.record!(@attrs)
    request_record.update!(key_possession_verified_at: Time.current)
    request_record.accept!(person: @person, device_id: "workstation-1", actor: "test")

    error = assert_raises(EnrollmentRequest::NotReady) do
      request_record.accept!(person: @person, device_id: "workstation-1", actor: "test")
    end
    assert_match(/already accepted/, error.message)
  end

  test "reject! is terminal for this key" do
    request_record = EnrollmentRequest.record!(@attrs)
    request_record.reject!(actor: "test")
    assert_equal "rejected", request_record.state

    error = assert_raises(EnrollmentRequest::NotReady) do
      request_record.reject!(actor: "test")
    end
    assert_match(/already rejected/, error.message)
  end
end
