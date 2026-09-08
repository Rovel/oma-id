require "test_helper"

# P0 consumer-path tests for the identity front and the public enrollment
# metadata endpoint (plan §11.4). These are lab-slice tests: no authentication
# or enrollment protocol is live on this server yet.
class IdentityFrontTest < ActionDispatch::IntegrationTest
  test "root renders the organization confirmation surface" do
    get root_path

    assert_response :success
    org = organizations(:lab)
    assert_match org.name, @response.body
    assert_match org.issuer, @response.body
    assert_match org.support_email, @response.body
    # Honest scope notice: a P0/P1 lab slice must not masquerade as a gate.
    assert_match(/P0\/P1 lab slice/, @response.body)
    assert_match(/No login or enrollment gate/, @response.body)
  end

  test "enrollment metadata serves public display information with no secrets" do
    org = organizations(:lab)
    get "/.well-known/oma-enrollment"

    assert_response :success
    body = JSON.parse(@response.body)
    assert_equal "oma-enrollment", body.dig("protocol", "name")
    assert_equal ["0"], body.dig("protocol", "versions")
    assert_equal org.issuer, body["issuer"]
    assert_equal org.name, body.dig("organization", "name")
    assert_equal org.support_email, body.dig("organization", "support_email")
    # Advertise only what this server actually serves (P2 wires the rest).
    assert_equal [], body["enrollment_methods"]
  end

  test "enrollment metadata fails closed when no organization is seeded" do
    Organization.delete_all
    get "/.well-known/oma-enrollment"

    assert_response :service_unavailable
    assert_equal({ "error" => "organization not configured" }, JSON.parse(@response.body))
  end
end
