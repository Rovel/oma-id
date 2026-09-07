require "test_helper"

class OrganizationTest < ActiveSupport::TestCase
  test "requires name, issuer, and support email" do
    org = Organization.new
    assert_not org.valid?
    assert org.errors[:name].present?
    assert org.errors[:issuer].present?
    assert org.errors[:support_email].present?
  end

  test "issuer must look like an origin and be unique" do
    dup = organizations(:lab).dup
    assert_not dup.valid?
    assert dup.errors[:issuer].present?

    bad = Organization.new(name: "X", issuer: "not-an-origin", support_email: "a@b.test")
    assert_not bad.valid?
    assert bad.errors[:issuer].present?
  end

  test "lab http issuer is permitted in this P0 slice" do
    org = Organization.new(
      name: "LAN Lab", issuer: "http://192.168.1.10:3000",
      support_email: "admin@lan.test"
    )
    assert org.valid?
  end
end
