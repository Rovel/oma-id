# A Person is the immutable directory identity (plan §5.1): email lives in
# LoginAlias records, display_name is presentation data, and the role is the
# §5.2 P1-a boundary (single-organization; RoleAssignment model comes later).
class Person < ApplicationRecord
  has_secure_password

  has_many :login_aliases, dependent: :destroy
  has_one :posix_identity_mapping, dependent: :destroy
  has_many :sessions, dependent: :destroy
  has_many :devices, dependent: :restrict_with_error

  enum :role, { owner: 0, identity_admin: 1, employee: 2 }, validate: true

  normalizes :display_name, with: ->(n) { n.strip }

  validates :display_name, presence: true

  # Authentication resolves the person through a login alias (§5.1: the
  # email is an alias, never the identity).
  def self.authenticate_by_alias(email_address:, password:)
    alias_record = LoginAlias.find_by(email_address: email_address.strip.downcase)
    person = alias_record&.person
    return nil unless person&.authenticate(password)

    person
  end

  def primary_email
    login_aliases.order(:created_at).first&.email_address
  end

  def owner?
    role == "owner"
  end

  def identity_admin?
    role == "identity_admin" || owner?
  end
end
