# frozen_string_literal: true

require "test_helper"
require "rake"

# Load the application's rake tasks once for this test file.
Rails.application.load_tasks

# P1-a administrator bootstrap (plan §21): explicit owner creation on an
# empty directory, idempotent re-run, §5.1 no automatic promotion.
class OmaIdBootstrapOwnerTest < ActiveSupport::TestCase
  test "bootstrap creates owner, alias, and audit event; re-run refuses" do
    assert_not Person.exists?, "directory starts empty"

    captured_password = nil
    io = StringIO.new
    # The task prints the generated password to stdout; capture it.
    original_stdout = $stdout
    Rake::Task["oma_id:bootstrap_owner"].reenable
    $stdout = io
    begin
      run_task_with_org("Bootstrap Lab")
    ensure
      $stdout = original_stdout
    end
    output = io.string

    owner = Person.find_by(role: :owner)
    assert_not_nil owner
    assert_equal "Organization Owner", owner.display_name
    assert_equal "owner@oma-id.invalid", owner.primary_email
    assert_not owner.authenticate("definitely-not-the-password"), "digest present but wrong password rejected"

    captured_password = output.lines.map(&:strip).find { |line| line.match?(/\A[\w-]{20,}\z/) }
    assert_not_nil captured_password, "generated password must be printed once (got: #{output.inspect})"
    assert owner.authenticate(captured_password), "printed password must work"

    assert AuditEvent.where(action: "person.bootstrap_owner", result: "success").exists?

    # Re-run must refuse: no silent promotion or duplicate owners (§5.1).
    e = assert_raises(SystemExit) do
      Rake::Task["oma_id:bootstrap_owner"].reenable
      run_task_with_org("Bootstrap Lab")
    end
    assert_equal 1, e.status
  end

  test "bootstrap honors a supplied password without printing it" do
    ENV["OMA_ID_BOOTSTRAP_PASSWORD"] = "supplied-password-1"
    io = StringIO.new
    original_stdout = $stdout
    Rake::Task["oma_id:bootstrap_owner"].reenable
    $stdout = io
    begin
      run_task_with_org("Supply Lab")
    ensure
      $stdout = original_stdout
      ENV.delete("OMA_ID_BOOTSTRAP_PASSWORD")
    end

    owner = Person.find_by(role: :owner)
    assert owner.authenticate("supplied-password-1")
    assert_not io.string.include?("supplied-password-1"), "supplied password must not be printed"
  end

  private

  def run_task_with_org(name)
    ENV["OMA_ID_ORG_NAME"] = name
    Rake.application.invoke_task("oma_id:bootstrap_owner[#{name}]")
  ensure
    ENV.delete("OMA_ID_ORG_NAME")
  end
end
