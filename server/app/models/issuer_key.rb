# frozen_string_literal: true

# Registry of issuer signing keys (ADR-0005): rotation metadata and audit.
# PUBLIC material only — private keys live in the secret store
# (rails credentials / injected env), never here, never in logs.
# key_id = SHA-256 of the raw public key (derived, never chosen).
class IssuerKey < ApplicationRecord
  PURPOSE = "lease_signing" # §5.3: one key pair per purpose
  STATES = %w[active retiring revoked].freeze

  validates :key_id, presence: true, uniqueness: { scope: :purpose }, length: { is: 64 }
  validates :public_key_hex, presence: true, length: { is: 64 }
  validates :purpose, presence: true, inclusion: { in: [PURPOSE] }
  validates :state, presence: true, inclusion: { in: STATES }

  # The key that signs new leases. Exactly one active key (ADR-0005 §4).
  def self.active_lease_signing_key
    find_by(purpose: PURPOSE, state: "active")
  end

  # ADR-0005 §2: key_id = SHA-256 of the raw 32-byte public key, hex.
  def self.derive_key_id(public_key_hex)
    Digest::SHA256.hexdigest([public_key_hex].pack("H*"))
  end

  # key_id derivation from a signing key's hex public key.
  def self.derive_key_id_from_public_hex(public_key_hex)
    derive_key_id(public_key_hex)
  end

  # Register a key from its raw public key bytes; the key_id is derived.
  def self.register!(public_key_hex:, state: "active")
    key_id = derive_key_id(public_key_hex)
    create!(
      key_id:,
      public_key_hex: public_key_hex.to_s.delete(" ").downcase,
      purpose: PURPOSE,
      state:
    )
  end
end
