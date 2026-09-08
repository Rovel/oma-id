# frozen_string_literal: true

require "test_helper"

# P1-a authentication tests (plan §5.1 password fallback, §16 audit).
class AuthenticationFlowTest < ActionDispatch::IntegrationTest
  setup do
    @person = Person.create!(
      display_name: "Ada Admin",
      role: :identity_admin,
      password: "correct-horse",
      password_confirmation: "correct-horse"
    )
    @person.login_aliases.create!(email_address: "ada@lab.test")
  end

  test "sign-in with a valid alias and password starts a session" do
    assert_not Session.exists?(person: @person)
    sign_in_as(@person, password: "correct-horse")
    assert Session.exists?(person: @person), "a server-side session row is created"
  end

  test "sign-in resolves the person through the login alias, never $USER" do
    # The alias exists on a different address than any convention; auth must
    # resolve through LoginAlias records only.
    assert_equal @person, Person.authenticate_by_alias(
      email_address: "ada@lab.test", password: "correct-horse"
    )
  end

  test "wrong password fails without revealing alias existence" do
    assert_nil Person.authenticate_by_alias(email_address: "ada@lab.test", password: "nope")
    # An unknown alias is indistinguishable from a wrong password (§16/§18).
    assert_nil Person.authenticate_by_alias(email_address: "nobody@lab.test", password: "x")
  end

  test "successful and failed sign-ins are audited" do
    sign_in_as(@person, password: "correct-horse")
    success = AuditEvent.where(action: "session.create", result: "success").last
    assert_not_nil success
    assert_match "ada@lab.test", success.actor

    delete session_url
    assert AuditEvent.where(action: "session.destroy", result: "success").exists?
  end

  test "failed sign-in is audited as anonymous failure" do
    post session_url, params: { email_address: "ada@lab.test", password: "nope" }
    failure = AuditEvent.where(action: "session.create", result: "failure").last
    assert_not_nil failure
    assert_equal "anonymous", failure.actor
  end

  test "sign-out terminates the session" do
    sign_in_as(@person, password: "correct-horse")
    assert Session.exists?(person: @person)
    sign_out
    assert_not Session.exists?(person: @person), "the session row is destroyed"
  end

  test "signed-out visitors can still see the public organization surface" do
    get root_path
    assert_response :success
  end
end
