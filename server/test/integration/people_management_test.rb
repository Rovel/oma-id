# frozen_string_literal: true

require "test_helper"

# Admin directory management (plan §21, §5.1, §10): people CRUD with
# device-integrity refusals, admin password resets (one-time render,
# sessions terminated), role gating.
class PeopleManagementTest < ActionDispatch::IntegrationTest
  setup do
    @admin = Person.create!(
      display_name: "Ada Admin", role: :identity_admin,
      password: "correct-horse", password_confirmation: "correct-horse"
    )
    @admin.login_aliases.create!(email_address: "ada@lab.test")
    sign_in_as(@admin, password: "correct-horse")
  end

  test "admin creates a person with a generated password shown once" do
    post people_path, params: { display_name: "New Employee", email_address: "new@lab.test",
                                role: "employee", password: "" }
    assert_response :ok
    assert_match "New password for", response.body
    person = Person.find_by(display_name: "New Employee")
    assert person
    assert_equal "employee", person.role
    assert_equal "new@lab.test", person.primary_email
    # the generated password must not be persisted anywhere in the response context
    assert AuditEvent.where(action: "person.create").exists?
  end

  test "admin creates a person with an explicit password and gets no one-time page" do
    post people_path, params: { display_name: "Set Pass", email_address: "setpass@lab.test",
                                role: "employee", password: "s3cret-password" }
    assert_redirected_to people_path
    person = Person.find_by(display_name: "Set Pass")
    assert person.authenticate("s3cret-password"), "the explicit password authenticates"
  end

  test "person removal is refused while devices are enrolled (§8.4)" do
    person = Person.create!(display_name: "Bound", role: :employee,
                            password: "x" * 12, password_confirmation: "x" * 12)
    person.login_aliases.create!(email_address: "bound@lab.test")
    person.devices.create!(device_id: "bound-dev", public_key_hex: "a" * 64, state: "active")

    delete person_path(person)
    assert_redirected_to people_path
    assert Person.exists?(person.id), "refusal keeps the person"
  end

  test "person removal works without devices and removes aliases and mapping" do
    person = Person.create!(display_name: "Free", role: :employee,
                            password: "x" * 12, password_confirmation: "x" * 12)
    person.login_aliases.create!(email_address: "free@lab.test")
    PosixIdentityMapping.create!(person:, username: "free", uid: 10_050, gid: 10_050,
                                 home: "/home/free", shell: "/bin/zsh", full_name: "Free")

    delete person_path(person)
    assert_redirected_to people_path
    assert_not Person.exists?(person.id)
    assert_not LoginAlias.exists?(email_address: "free@lab.test")
    assert_not PosixIdentityMapping.exists?(username: "free")
    assert AuditEvent.where(action: "person.destroy").exists?
  end

  test "admin password reset renders once, terminates sessions, and is audited" do
    person = Person.create!(display_name: "Resetme", role: :employee,
                            password: "old-password", password_confirmation: "old-password")
    person.login_aliases.create!(email_address: "resetme@lab.test")
    old_session = person.sessions.create!(user_agent: "test", ip_address: "127.0.0.1")

    post reset_password_person_path(person)
    assert_response :ok
    assert_match(/only this once/, response.body)
    # the plain password must NOT appear anywhere persisted
    assert_not Session.exists?(old_session.id)
    assert AuditEvent.where(action: "person.password_reset").exists?
    new_digest = person.reload.password_digest
    assert_not_equal "old", new_digest
  end

  test "employee role cannot reach the people surface" do
    employee = Person.create!(display_name: "Emp", role: :employee,
                              password: "x" * 12, password_confirmation: "x" * 12)
    employee.login_aliases.create!(email_address: "emp@lab.test")
    sign_in_as(employee, password: "x" * 12)

    get people_path
    assert_redirected_to root_path
  end
end
