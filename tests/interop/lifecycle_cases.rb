# frozen_string_literal: true

# Additional cases share the protocol harness; no alternative authentication app.
class ProtocolTest
  def refresh(result, client: @client)
    post "/oauth/token", grant_type: "refresh_token", client_id: client.uid,
                          refresh_token: result.fetch("refresh_token")
    json
  end

  def userinfo(result)
    get "/oauth/userinfo", {}, "HTTP_AUTHORIZATION" => "Bearer #{result.fetch('access_token')}"
  end

  def public_keys
    get "/oauth/discovery/keys"
    assert_equal 200, last_response.status
    json
  end

  def verify_with_jwks(token, keys)
    JWT.decode(token, nil, true, algorithms: ["RS256"], jwks: keys,
               verify_iss: true, iss: Lab::ISSUER, verify_aud: true, aud: @client.uid).first
  end

  def test_signing_key_rotation_overlap_and_retirement
    old_token = token_response.fetch("id_token")
    old_keys = public_keys
    next_key = OpenSSL::PKey::RSA.generate(2048)
    Lab.signing_keys = [next_key.to_pem, Lab::KEY.to_pem]
    new_token = token_response.fetch("id_token")
    overlapping_keys = public_keys
    assert_equal 2, overlapping_keys.fetch("keys").size
    assert_equal Lab::PERSON.subject, verify_with_jwks(old_token, overlapping_keys).fetch("sub")
    assert_equal Lab::PERSON.subject, verify_with_jwks(new_token, overlapping_keys).fetch("sub")
    old_kid = JWT.decode(old_token, nil, false).last.fetch("kid")
    new_kid = JWT.decode(new_token, nil, false).last.fetch("kid")
    refute_equal old_kid, new_kid
    assert_raises(JWT::DecodeError) { verify_with_jwks(new_token, old_keys) }

    Lab.signing_keys = [next_key.to_pem]
    retired_keys = public_keys
    assert_equal [new_kid], retired_keys.fetch("keys").map { |key| key.fetch("kid") }
    assert_raises(JWT::DecodeError) { verify_with_jwks(old_token, retired_keys) }
    assert_equal Lab::PERSON.subject, verify_with_jwks(new_token, retired_keys).fetch("sub")
    # A verifier retaining old JWKS can still validate an unexpired old token.
    assert_equal Lab::PERSON.subject, verify_with_jwks(old_token, old_keys).fetch("sub")
  end

  def test_revoking_refresh_token_rejects_refresh_and_userinfo
    issued = token_response
    post "/oauth/revoke", client_id: @client.uid, token: issued.fetch("refresh_token"), token_type_hint: "refresh_token"
    assert_equal 200, last_response.status
    assert_equal "invalid_grant", refresh(issued).fetch("error")
    userinfo(issued)
    assert_equal 401, last_response.status
    # Signed ID tokens already held by a relying party remain cryptographically valid.
    assert_equal Lab::PERSON.subject, verify(issued.fetch("id_token")).fetch("sub")
  end

  def test_other_client_cannot_revoke_or_refresh_an_issued_token
    issued = token_response
    other = Doorkeeper::Application.create!(name: "Other", redirect_uri: REDIRECT, confidential: false)
    post "/oauth/revoke", client_id: other.uid, token: issued.fetch("refresh_token"), token_type_hint: "refresh_token"
    assert_equal 403, last_response.status
    assert_equal "invalid_grant", refresh(issued, client: other).fetch("error")
    userinfo(issued)
    assert_equal 200, last_response.status
    assert refresh(issued).key?("access_token")
  end

  def test_explicit_lab_disablement_revokes_existing_and_approved_device_credentials
    issued = token_response
    approved = device_request
    approve(approved)
    pending = device_request
    Lab.disable_person!

    userinfo(issued)
    assert_equal 401, last_response.status
    assert_equal "invalid_grant", refresh(issued).fetch("error")
    assert_equal "invalid_grant", poll(approved).fetch("error")
    post "/oauth/device", user_code: pending.fetch("user_code")
    assert_equal 401, last_response.status
    assert_equal "authorization_pending", poll(pending).fetch("error")
    get "/oauth/authorize", client_id: @client.uid, redirect_uri: REDIRECT, response_type: "code",
                             scope: "openid", code_challenge: "a" * 43, code_challenge_method: "S256"
    assert_equal 401, last_response.status
    assert_equal Lab::PERSON.subject, verify(issued.fetch("id_token")).fetch("sub")
  end

  def test_code_flow_explicit_denial_does_not_issue_credentials
    verifier = SecureRandom.urlsafe_base64(48)
    challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
    delete "/oauth/authorize", client_id: @client.uid, redirect_uri: REDIRECT,
                               response_type: "code", scope: "openid", state: "denial-state",
                               code_challenge: challenge, code_challenge_method: "S256"
    assert_equal 302, last_response.status
    location = URI(last_response.headers.fetch("location"))
    assert_equal REDIRECT, "#{location.scheme}://#{location.host}#{location.path}"
    params = URI.decode_www_form(location.query).to_h
    assert_equal "access_denied", params.fetch("error")
    assert_equal "denial-state", params.fetch("state")
    assert_equal 0, Doorkeeper::AccessGrant.where(application_id: @client.id).count
    assert_equal 0, Doorkeeper::AccessToken.where(application_id: @client.id).count
  end

  def test_device_denial_is_terminal_until_expiry
    device = device_request
    if ENV["OMA_P0_RAW"] == "1"
      assert Lab::Application.routes.routes.any? { |route| route.verb == "DELETE" && route.path.spec.to_s == "/oauth/device(.:format)" },
             "Raw dependencies have no device denial route for the proposed lab contract"
    end
    delete "/oauth/device", user_code: device.fetch("user_code")
    assert_equal 204, last_response.status
    assert_equal "access_denied", poll(device).fetch("error")
    assert_equal 400, last_response.status
    assert_equal "no-store", last_response.headers["cache-control"]
    assert_equal "access_denied", poll(device).fetch("error")
    post "/oauth/device", user_code: device.fetch("user_code")
    assert_equal 422, last_response.status
    assert_equal 0, Doorkeeper::AccessToken.where(application_id: @client.id).count
    travel 601.seconds do
      assert_equal "expired_token", poll(device).fetch("error")
    end
  end

  def test_device_denial_cannot_change_an_approved_grant
    device = device_request
    approve(device)
    # This probe is about our explicit adapter contract; raw coverage above
    # records that the dependencies provide no such endpoint.
    skip "Lab denial adapter is intentionally absent in raw mode" if ENV["OMA_P0_RAW"] == "1"

    delete "/oauth/device", user_code: device.fetch("user_code")
    assert_equal 422, last_response.status
    assert poll(device).key?("access_token")
  end

  def test_disabled_person_cannot_deny_pending_device
    device = device_request
    skip "Lab denial adapter is intentionally absent in raw mode" if ENV["OMA_P0_RAW"] == "1"

    Lab.disable_person!
    delete "/oauth/device", user_code: device.fetch("user_code")
    assert_equal 401, last_response.status
    assert_equal "authorization_pending", poll(device).fetch("error")
  end

  def test_denied_device_does_not_disclose_state_to_a_different_client
    skip "Lab denial adapter is intentionally absent in raw mode" if ENV["OMA_P0_RAW"] == "1"
    device = device_request
    delete "/oauth/device", user_code: device.fetch("user_code")
    assert_equal 204, last_response.status
    other = Doorkeeper::Application.create!(name: "Other", redirect_uri: REDIRECT, confidential: false)
    assert_equal "invalid_grant", poll(device, client: other).fetch("error")
    assert_equal "access_denied", poll(device).fetch("error")
  end

  # These gates run by default with the adapter. Raw mode can opt in to preserve
  # the historical failures without the family implementation.
  if ENV["OMA_P0_RAW"] != "1" || ENV["OMA_P0_LIFECYCLE_GATES"] == "1"
    def test_replay_of_ancestor_revokes_current_refresh_family
      initial = token_response
      replacement = refresh(initial)
      assert_equal 200, last_response.status
      assert_equal "invalid_grant", refresh(initial).fetch("error")
      userinfo(replacement)
      assert_equal 401, last_response.status, "Replay must invalidate descendant access"
      assert_equal "invalid_grant", refresh(replacement).fetch("error")
    end

    def test_replay_of_ancestor_prevents_descendant_refresh
      initial = token_response
      replacement = refresh(initial)
      assert_equal 200, last_response.status
      assert_equal "invalid_grant", refresh(initial).fetch("error")
      response = refresh(replacement)
      assert_equal "invalid_grant", response["error"], "Descendant refresh must fail after ancestor replay"
    end
  end
end
