# frozen_string_literal: true

require "timeout"
require "open3"

class ProtocolTest
  def family_for(result)
    token = Doorkeeper::AccessToken.by_token(result.fetch("access_token"))
    Lab::TokenFamily.find(Lab::FamilyMember.find_by!(token_id: token.id).family_id)
  end

  def refresh_params(result)
    {grant_type: "refresh_token", client_id: @client.uid, refresh_token: result.fetch("refresh_token")}
  end

  def independent_refresh(result)
    session = Rack::Test::Session.new(Rack::MockSession.new(app))
    session.header "Host", "issuer.oma.test"
    session.post "/oauth/token", refresh_params(result)
    [session.last_response.status, JSON.parse(session.last_response.body)]
  end

  # Hold the real PostgreSQL person lock until every worker is observed waiting
  # on it. This proves contention instead of relying on scheduler timing.
  def contending(*operations)
    threads = []
    Lab::FamilyLifecycle.with_person do
      threads = operations.map do |operation|
        Thread.new do
          Thread.current.report_on_exception = false
          ActiveRecord::Base.connection_pool.with_connection { operation.call }
        end
      end
      connection = ActiveRecord::Base.connection
      Timeout.timeout(10) do
        loop do
          connection.execute("SELECT pg_stat_clear_snapshot()")
          waiting = connection.execute(<<~SQL).first.fetch("count").to_i
            SELECT count(*) FROM pg_stat_activity
            WHERE application_name = current_setting('application_name')
              AND pid <> pg_backend_pid() AND wait_event_type = 'Lock'
          SQL
          break if waiting >= operations.size
          raise threads.find { |thread| !thread.alive? }.value.inspect if threads.any? { |thread| !thread.alive? }
          sleep 0.01
        end
      end
    end
    Timeout.timeout(10) { threads.map(&:value) }
  ensure
    threads.each { |thread| thread.kill if thread.alive? }
    threads.each(&:join)
  end

  def test_older_ancestor_replay_revokes_only_its_family
    root = token_response
    unrelated = token_response
    child = refresh(root)
    grandchild = refresh(child)
    affected = family_for(root)
    refute_equal affected.id, family_for(unrelated).id
    assert_equal affected.id, family_for(grandchild).id
    assert_equal "invalid_grant", refresh(root).fetch("error")
    userinfo(grandchild)
    assert_equal 401, last_response.status
    assert_equal "invalid_grant", refresh(grandchild).fetch("error")
    userinfo(unrelated)
    assert_equal 200, last_response.status
    assert refresh(unrelated).key?("access_token")
    assert_equal 1, Lab::LifecycleEvent.where(family_id: affected.id, action: "replay_revoked").count
    refresh(root)
    assert_equal 1, Lab::LifecycleEvent.where(family_id: affected.id, action: "replay_revoked").count
  end

  def test_wrong_client_replay_does_not_revoke_victims_family
    root = token_response
    child = refresh(root)
    other = Doorkeeper::Application.create!(name: "Other", redirect_uri: REDIRECT, confidential: false)
    assert_equal "invalid_grant", refresh(root, client: other).fetch("error")
    assert_nil family_for(root).reload.revoked_at
    userinfo(child)
    assert_equal 200, last_response.status
    assert refresh(child).key?("access_token")
  end

  def test_revoking_an_ancestor_revokes_descendants_but_not_another_family
    root = token_response
    child = refresh(root)
    unrelated = token_response
    post "/oauth/revoke", client_id: @client.uid, token: root.fetch("refresh_token"), token_type_hint: "refresh_token"
    assert_equal 200, last_response.status
    userinfo(child)
    assert_equal 401, last_response.status
    assert_equal "invalid_grant", refresh(child).fetch("error")
    userinfo(unrelated)
    assert_equal 200, last_response.status
  end

  def test_bad_confidential_client_secret_cannot_revoke_family
    @client.update!(confidential: true)
    header "Authorization", "Basic #{Base64.strict_encode64("#{@client.uid}:#{@client.secret}")}"
    root = token_response
    child = refresh(root)
    header "Authorization", "Basic #{Base64.strict_encode64("#{@client.uid}:wrong-secret")}"
    response = refresh(root)
    assert_operator last_response.status, :>=, 400
    assert response.key?("error")
    assert_nil family_for(root).reload.revoked_at
    header "Authorization", "Basic #{Base64.strict_encode64("#{@client.uid}:#{@client.secret}")}"
    assert refresh(child).key?("access_token")
  ensure
    header "Authorization", nil
  end

  def test_family_metadata_cannot_be_selected_by_request_parameters
    unrelated = token_response
    family = family_for(unrelated)
    device = device_request
    approve(device)
    post "/oauth/token", grant_type: DEVICE_GRANT, client_id: @client.uid,
                          device_code: device.fetch("device_code"), family_id: family.id,
                          parent_id: Lab::FamilyMember.where(family_id: family.id).first.id
    assert_equal 200, last_response.status
    refute_equal family.id, family_for(json).id
  end

  def test_secrets_are_hashed_and_audit_contains_only_references
    root = token_response
    row = Doorkeeper::AccessToken.by_token(root.fetch("access_token"))
    assert row.token != root.fetch("access_token"), "Access secret must be hashed"
    assert row.refresh_token != root.fetch("refresh_token"), "Refresh secret must be hashed"
    event = Lab::LifecycleEvent.find_by!(token_id: row.id, action: "issued")
    assert_equal family_for(root).id, event.family_id
    assert !event.attributes.to_json.include?(root.fetch("refresh_token")), "Audit must not contain refresh secrets"
    assert !event.attributes.to_json.include?(root.fetch("access_token")), "Audit must not contain access secrets"
  end

  def test_simultaneous_refresh_issues_once_then_revokes_the_family
    root = token_response
    results = contending(-> { independent_refresh(root) }, -> { independent_refresh(root) })
    assert_equal [200, 400], results.map(&:first).sort
    issued = results.find { |status, _| status == 200 }.last
    userinfo(issued)
    assert_equal 401, last_response.status
    assert_equal "invalid_grant", refresh(issued).fetch("error")
    assert_equal 2, Lab::FamilyMember.where(family_id: family_for(root).id).count
  end

  def test_refresh_contending_with_disablement_cannot_leave_live_credentials
    root = token_response
    results = contending(-> { independent_refresh(root) }, -> { Lab.disable_person!; :disabled })
    status, issued = results.first
    assert_includes [200, 400], status
    assert_equal false, Lab::PERSON.enabled
    assert_equal "invalid_grant", refresh(root).fetch("error")
    if status == 200
      userinfo(issued)
      assert_equal 401, last_response.status
      assert_equal "invalid_grant", refresh(issued).fetch("error")
    end
    assert_equal 0, Doorkeeper::AccessToken.where(resource_owner_id: Lab::PERSON.id, revoked_at: nil).count
  end

  def test_audit_failure_rolls_back_refresh_consumption_and_issuance
    root = token_response
    count = Doorkeeper::AccessToken.count
    connection = ActiveRecord::Base.connection
    # A real database failure, not a mocked implementation return value.
    connection.add_check_constraint :lab_lifecycle_events, "action <> 'rotated'", name: "lab_reject_rotation", validate: false
    begin
      assert_raises(ActiveRecord::StatementInvalid) { refresh(root) }
    ensure
      connection.remove_check_constraint :lab_lifecycle_events, name: "lab_reject_rotation"
    end
    assert_equal count, Doorkeeper::AccessToken.count
    assert_equal 1, Lab::FamilyMember.where(family_id: family_for(root).id).count
    assert_nil Doorkeeper::AccessToken.by_token(root.fetch("access_token")).revoked_at
    assert refresh(root).key?("access_token")
  end

  def test_fresh_process_can_revoke_family_from_persisted_ancestor
    root = token_response
    child = refresh(root)
    input = JSON.generate(schema: ActiveRecord::Base.connection.schema_search_path, params: refresh_params(root))
    output, status = Open3.capture2(RbConfig.ruby, File.join(__dir__, "family_probe.rb"), stdin_data: input)
    assert status.success?, "Fresh-process probe must complete"
    result = JSON.parse(output)
    assert_equal 400, result.fetch("status")
    assert_equal "invalid_grant", result.fetch("error")
    userinfo(child)
    assert_equal 401, last_response.status
    assert_equal "invalid_grant", refresh(child).fetch("error")
  end

  def test_audit_failure_rolls_back_replay_revocation_and_retry_completes_it
    root = token_response
    child = refresh(root)
    family = family_for(root)
    connection = ActiveRecord::Base.connection
    connection.add_check_constraint :lab_lifecycle_events, "action <> 'replay_revoked'", name: "lab_reject_replay_audit", validate: false
    begin
      assert_raises(ActiveRecord::StatementInvalid) { refresh(root) }
    ensure
      connection.remove_check_constraint :lab_lifecycle_events, name: "lab_reject_replay_audit"
    end
    assert_nil family.reload.revoked_at
    assert_equal 0, Lab::LifecycleEvent.where(family_id: family.id, action: "replay_revoked").count
    userinfo(child)
    assert_equal 200, last_response.status
    assert_equal "invalid_grant", refresh(root).fetch("error")
    userinfo(child)
    assert_equal 401, last_response.status
    assert_equal 1, Lab::LifecycleEvent.where(family_id: family.id, action: "replay_revoked").count
  end
end
