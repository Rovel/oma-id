# §5.1: a login alias is an email bound to an immutable Person. Aliases are
# unique; changing one must never create a new person or transfer access.
class LoginAlias < ApplicationRecord
  belongs_to :person

  normalizes :email_address, with: ->(e) { e.strip.downcase }

  validates :email_address,
            presence: true,
            uniqueness: true,
            format: { with: URI::MailTo::EMAIL_REGEXP }
end
