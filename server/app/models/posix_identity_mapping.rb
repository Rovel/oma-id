# frozen_string_literal: true

# Durable POSIX identity mapping (plan §8.4/§16): a managed username, UID,
# GID, home and shell for a Person. The server is authoritative; the agent
# reconciles the local account from this record.
#
# Managed range (§8.4 "reserve a managed UID/GID range"): 10000-19999.
# IDs are never recycled while a retained record could still refer to them.
class PosixIdentityMapping < ApplicationRecord
  MANAGED_RANGE = (10_000..19_999).freeze
  RESERVED_NAMES = %w[
    root daemon bin sys sync games man lp mail news uucp proxy www-data
    backup list irc gnats nobody systemd-network systemd-resolve systemd-timesync
    messagebus uuidd omachi omarchy oma-id dbus avahi sshd tss
  ].freeze
  DEFAULT_SHELL = "/bin/zsh" # Omarchy default shell

  belongs_to :person

  normalizes :username, with: ->(u) { u.strip.downcase }

  validates :username,
            presence: true,
            uniqueness: true,
            length: { maximum: 32 },
            format: { with: /\A[a-z_][a-z0-9_-]*\z/ },
            exclusion: { in: RESERVED_NAMES, message: "is a reserved system name" }
  validates :uid,
            presence: true,
            uniqueness: true,
            numericality: { only_integer: true },
            inclusion: { in: MANAGED_RANGE, message: "must be in the managed range #{MANAGED_RANGE}" }
  validates :gid,
            presence: true,
            uniqueness: true,
            numericality: { only_integer: true },
            inclusion: { in: MANAGED_RANGE, message: "must be in the managed range #{MANAGED_RANGE}" }
  validates :home,
            presence: true,
            format: { with: %r{\A/home/[a-z0-9_-]+\z} }
  validates :shell, presence: true
  validates :full_name, length: { maximum: 128 }, allow_nil: true

  # Derive a safe local username from a login alias's local part (§8.4:
  # safe local username, case normalization, reserved names, Unicode input).
  # Appends a numeric suffix on collision; returns nil when nothing derivable
  # remains.
  def self.derive_username(alias_email)
    base = alias_email.to_s.split("@").first.to_s
             .downcase
             .gsub(/[^a-z0-9_-]/, "")
             .slice(0, 24)
    return nil if base.empty? || base.match?(/\A[-_]/)

    candidate = base
    suffix = 1
    while RESERVED_NAMES.include?(candidate) || exists?(username: candidate)
      suffix += 1
      candidate = "#{base}#{suffix}"
      return nil if suffix > 999
    end
    candidate
  end

  # Allocate the next free uid/gid pair in the managed range.
  def self.allocate_uid!
    used = pluck(:uid).to_set
    candidate = MANAGED_RANGE.find { |uid| !used.include?(uid) }
    raise "managed UID range exhausted" unless candidate

    candidate
  end
end
