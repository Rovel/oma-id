# frozen_string_literal: true

class ProtocolTest
  def test_device_scope_cannot_exceed_server_or_client_permissions
    @client.update!(scopes: "openid")
    ["openid administrator", "openid profile"].each do |scope|
      post "/oauth/authorize_device", client_id: @client.uid, scope: scope
      assert_equal 400, last_response.status
      assert_equal "invalid_scope", json.fetch("error")
      assert_equal 0, Doorkeeper::DeviceAuthorizationGrant::DeviceGrant.where(application_id: @client.id).count
    end
  end

  def test_unsigned_and_symmetric_algorithm_substitution_are_rejected
    claims = verify(token_response.fetch("id_token"))
    unsigned = JWT.encode(claims, nil, "none")
    substituted = JWT.encode(claims, Lab::KEY.public_key.to_pem, "HS256")
    [unsigned, substituted].each do |token|
      assert_raises(JWT::IncorrectAlgorithm) { verify(token) }
    end
  end

  def test_discovery_rejects_untrusted_host_and_forwarded_host
    ["Host", "X-Forwarded-Host"].each do |name|
      header name, "attacker.invalid"
      get "/.well-known/openid-configuration"
      assert_equal 403, last_response.status
      refute_includes last_response.body, '"issuer"'
      header name, name == "Host" ? "issuer.oma.test" : nil
    end
  end

  def test_unknown_authorization_scope_does_not_issue_code
    header "Accept", "text/html"
    get "/oauth/authorize", client_id: @client.uid, redirect_uri: REDIRECT,
      response_type: "code", scope: "openid administrator",
      code_challenge: "a" * 43, code_challenge_method: "S256"
    assert_equal 400, last_response.status
    assert_nil last_response.headers["location"]
    assert_equal 0, Doorkeeper::AccessGrant.where(application_id: @client.id).count
  end
end
