# frozen_string_literal: true

# P1-a session test helper (adapted from the Rails 8 authentication
# generator's helper to the Person + LoginAlias domain).
module SessionTestHelper
  def sign_in_as(person, password: "password1")
    post session_url, params: { email_address: person.primary_email, password: }
    assert_response :redirect
    follow_redirect!
    person
  end

  def sign_out
    delete session_url
  end
end

module ActionDispatch
  class IntegrationTest
    include SessionTestHelper
  end
end
