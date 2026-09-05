# frozen_string_literal: true

require_relative "issuer"
require "minitest/autorun"
require "rack/test"
require "active_support/testing/time_helpers"

class ProtocolTest < Minitest::Test
  include Rack::Test::Methods
  include ActiveSupport::Testing::TimeHelpers

  DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
  REDIRECT = "https://client.oma.test/callback"

  def app = Lab::Application

  def setup
    Lab::PERSON.enabled = true
    Lab.signing_keys = [Lab::KEY.to_pem]
    clear_cookies
    header "Host", "issuer.oma.test"
    header "Accept", "application/json"
    @client = Doorkeeper::Application.create!(name: "Lab broker", redirect_uri: REDIRECT,
                                             scopes: "openid profile", confidential: false)
  end

  def teardown
    travel_back
    Lab::PERSON.enabled = true
    Lab.signing_keys = [Lab::KEY.to_pem]
  end

  def json = JSON.parse(last_response.body)

  def device_request
    post "/oauth/authorize_device", client_id: @client.uid, scope: "openid profile"
    assert_equal 200, last_response.status
    json
  end

  def poll(device, client: @client)
    post "/oauth/token", grant_type: DEVICE_GRANT, client_id: client.uid, device_code: device.fetch("device_code")
    json
  end

  def approve(device)
    post "/oauth/device", user_code: device.fetch("user_code")
    assert_equal 204, last_response.status
  end

  def token_response
    device = device_request
    approve(device)
    result = poll(device)
    assert_equal 200, last_response.status
    result
  end

  def verify(token, audience: @client.uid, issuer: Lab::ISSUER)
    JWT.decode(token, Lab::KEY.public_key, true, algorithms: ["RS256"],
               verify_iss: true, iss: issuer, verify_aud: true, aud: audience).first
  end

  def test_device_flow_issues_verifiable_id_token_and_matching_userinfo
    result = token_response
    assert result.key?("id_token"), "Device grant must issue an ID token"
    claims = verify(result.fetch("id_token"))
    assert_equal Lab::PERSON.subject, claims.fetch("sub")
    assert result.key?("refresh_token")
    get "/oauth/userinfo", {}, "HTTP_AUTHORIZATION" => "Bearer #{result.fetch('access_token')}"
    assert_equal 200, last_response.status
    assert_equal claims.fetch("sub"), json.fetch("sub")
  end

  def test_pending_slowdown_and_expiry
    device = device_request
    assert_equal "authorization_pending", poll(device).fetch("error")
    assert_equal "slow_down", poll(device).fetch("error")
    travel 601.seconds do
      assert_equal "expired_token", poll(device).fetch("error")
    end
  end

  def test_device_code_cannot_be_redeemed_twice
    device = device_request
    approve(device)
    assert poll(device).key?("access_token")
    assert_equal "invalid_grant", poll(device).fetch("error")
  end

  def test_device_code_is_bound_to_client
    device = device_request
    approve(device)
    other = Doorkeeper::Application.create!(name: "Other", redirect_uri: REDIRECT, confidential: false)
    assert_equal "invalid_grant", poll(device, client: other).fetch("error")
    assert poll(device).key?("access_token")
  end

  def test_wrong_issuer_audience_key_and_expired_id_tokens_are_rejected
    token = token_response.fetch("id_token")
    assert_raises(JWT::InvalidIssuerError) { verify(token, issuer: "https://wrong.oma.test") }
    assert_raises(JWT::InvalidAudError) { verify(token, audience: "wrong-client") }
    assert_raises(JWT::VerificationError) do
      JWT.decode(token, OpenSSL::PKey::RSA.generate(2048).public_key, true, algorithms: ["RS256"])
    end
    travel 601.seconds do
      assert_raises(JWT::ExpiredSignature) { verify(token) }
    end
  end

  def test_password_and_implicit_flows_are_unavailable
    post "/oauth/token", grant_type: "password", client_id: @client.uid, username: "fake", password: "fake"
    assert_equal "unsupported_grant_type", json.fetch("error")
    header "Accept", "text/html"
    get "/oauth/authorize", client_id: @client.uid, redirect_uri: REDIRECT, response_type: "token", scope: "openid"
    refute_includes last_response.headers.fetch("location", ""), "access_token="
    assert_equal 400, last_response.status
    assert_equal 0, Doorkeeper::AccessToken.where(application_id: @client.id).count
  end

  def test_discovery_advertises_device_grant_uri
    get "/.well-known/openid-configuration"
    assert_equal 200, last_response.status
    metadata = json
    assert_equal Lab::ISSUER, metadata.fetch("issuer")
    assert_includes metadata.fetch("grant_types_supported"), DEVICE_GRANT
  end

  def test_discovery_advertises_device_authorization_endpoint
    get "/.well-known/openid-configuration"
    assert_equal "#{Lab::ISSUER}/oauth/authorize_device", json["device_authorization_endpoint"]
  end

  def test_jwks_verifies_device_id_token_without_private_material
    token = token_response.fetch("id_token")
    get "/.well-known/openid-configuration"
    metadata = json
    get URI(metadata.fetch("jwks_uri")).path
    assert_equal 200, last_response.status
    refute_empty json.fetch("keys")
    refute json.fetch("keys").first.key?("d"), "JWKS must not expose a private key"
    claims, = JWT.decode(token, nil, true, algorithms: ["RS256"], jwks: json,
                         verify_iss: true, iss: Lab::ISSUER, verify_aud: true, aud: @client.uid)
    assert_equal Lab::PERSON.subject, claims.fetch("sub")
  end

  def test_refresh_rotation_and_old_refresh_replay
    initial = token_response
    post "/oauth/token", grant_type: "refresh_token", client_id: @client.uid, refresh_token: initial.fetch("refresh_token")
    assert_equal 200, last_response.status
    replacement = json
    refute_equal initial.fetch("refresh_token"), replacement.fetch("refresh_token")
    verify(replacement.fetch("id_token"))
    post "/oauth/token", grant_type: "refresh_token", client_id: @client.uid, refresh_token: initial.fetch("refresh_token")
    assert_equal "invalid_grant", json.fetch("error")
  end

  def test_code_pkce_nonce_and_replay
    verifier = SecureRandom.urlsafe_base64(48)
    challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
    get "/oauth/authorize", client_id: @client.uid, redirect_uri: REDIRECT, response_type: "code",
                             scope: "openid", nonce: "lab-nonce", state: "lab-state",
                             code_challenge: challenge, code_challenge_method: "S256"
    assert_equal 302, last_response.status
    query = URI.decode_www_form(URI(last_response.headers.fetch("location")).query).to_h
    assert_equal "lab-state", query.fetch("state")
    params = {grant_type: "authorization_code", client_id: @client.uid, redirect_uri: REDIRECT,
              code: query.fetch("code"), code_verifier: verifier}
    post "/oauth/token", params.merge(code_verifier: "incorrect")
    assert_equal "invalid_grant", json.fetch("error")
    post "/oauth/token", params
    assert_equal 200, last_response.status
    assert_equal "lab-nonce", verify(json.fetch("id_token")).fetch("nonce")
    post "/oauth/token", params
    assert_equal "invalid_grant", json.fetch("error")
  end

  def test_authorization_requires_s256_pkce
    header "Accept", "text/html"
    params = {client_id: @client.uid, redirect_uri: REDIRECT, response_type: "code", scope: "openid"}
    [params, params.merge(code_challenge: "a" * 43, code_challenge_method: "plain")].each do |request|
      get "/oauth/authorize", request
      assert_equal 400, last_response.status
      assert_nil last_response.headers["location"]
      assert_equal 0, Doorkeeper::AccessGrant.where(application_id: @client.id).count
    end
  end

  def test_redirect_uri_suffix_is_rejected_without_redirecting_to_attacker
    header "Accept", "text/html"
    get "/oauth/authorize", client_id: @client.uid, redirect_uri: "#{REDIRECT}/attacker",
                             response_type: "code", scope: "openid",
                             code_challenge: "a" * 43, code_challenge_method: "S256"
    assert_equal 400, last_response.status
    assert_nil last_response.headers["location"]
    assert_equal 0, Doorkeeper::AccessGrant.where(application_id: @client.id).count
  end

  def test_unknown_client_cannot_start_device_flow
    post "/oauth/authorize_device", client_id: "unknown-client", scope: "openid"
    assert_equal "invalid_client", json.fetch("error")
    assert_operator last_response.status, :>=, 400
  end
end

require_relative "lifecycle_cases"
require_relative "negative_cases"
require_relative "family_cases" unless ENV["OMA_P0_RAW"] == "1"
