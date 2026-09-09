# frozen_string_literal: true

# P1-a administrator bootstrap (plan §21): creates the organization (if
# missing) and its first owner explicitly — §5.1 forbids promoting the first
# managed user to owner automatically. The owner password is either supplied
# via OMA_ID_BOOTSTRAP_PASSWORD or generated and printed ONCE to stdout
# (never stored in logs, never sent anywhere).
#
# Usage:
#   bin/rails oma_id:bootstrap_owner[\"Org Name\"]            # generated password
#   OMA_ID_BOOTSTRAP_PASSWORD=... bin/rails oma_id:bootstrap_owner
# Idempotent: safe to re-run; re-running reports the existing owner and exits.

namespace :oma_id do
  desc "Bootstrap the organization owner (idempotent; password printed once unless OMA_ID_BOOTSTRAP_PASSWORD is set)"
  task :bootstrap_owner, [:org_name] => :environment do |_task, args|
    org_name = args[:org_name] || ENV.fetch("OMA_ID_ORG_NAME", "OMA-ID Lab")

    if Person.exists?
      owner = Person.find_by(role: :owner)
      abort "oma-id: people already exist; bootstrap only runs on an empty directory " \
            "(existing owner: #{owner&.primary_email || 'none'})"
    end

    password = ENV["OMA_ID_BOOTSTRAP_PASSWORD"]
    generated = password.blank?
    password ||= SecureRandom.base58(20)

    email = ENV.fetch("OMA_ID_BOOTSTRAP_EMAIL", "owner@oma-id.invalid")
    display_name = ENV.fetch("OMA_ID_BOOTSTRAP_NAME", "Organization Owner")

    person = nil
    ActiveRecord::Base.transaction do
      person = Person.create!(
        display_name:,
        role: :owner,
        password:,
        password_confirmation: password
      )
      person.login_aliases.create!(email_address: email)
    end

    AuditEvent.record!(actor: "bootstrap", action: "person.bootstrap_owner", target: email, result: "success",
                       metadata: { display_name: })

    if generated
      puts "=" * 60
      puts "Owner password (printed once; store it in your password manager):"
      puts password
      puts "=" * 60
    else
      puts "Owner password taken from OMA_ID_BOOTSTRAP_PASSWORD."
    end
    puts "Owner: #{display_name} <#{email}> role=owner org=#{org_name}"
  end
end

namespace :oma_id do
  desc "Register a managed device for a person (technician pre-provisioning, §6.3): " \
       "bin/rails \"oma_id:register_device[email,device_id,public_key_hex]\""
  task :register_device, %i[email device_id public_key_hex] => :environment do |_task, args|
    email, device_id, public_key_hex = args[:email].to_s, args[:device_id].to_s, args[:public_key_hex].to_s

    person = Person.joins(:login_aliases).find_by(login_aliases: { email_address: email.strip.downcase })
    abort "oma-id: no person with alias #{email}" unless person
    abort "oma-id: public_key_hex must be 64 hex chars" unless public_key_hex.match?(/\A[0-9a-f]{64}\z/)

    device = Device.find_or_initialize_by(device_id:)
    if device.persisted?
      puts "Device #{device_id} already exists (#{device.state}, person #{device.person_id})."
    else
      device.update!(person:, public_key_hex:, state: "active")

      # §8.4: durable POSIX mapping, allocated by the server at provisioning.
      mapping = PosixIdentityMapping.find_or_create_by!(person:) do |m|
        username = ENV["OMA_ID_POSIX_USERNAME"] ||
                   PosixIdentityMapping.derive_username(email) ||
                   raise("cannot derive a safe POSIX username from #{email}")
        uid = PosixIdentityMapping.allocate_uid!
        m.assign_attributes(
          username:, uid:, gid: uid, # primary group matches the UID (user-private groups)
          home: "/home/#{username}", shell: PosixIdentityMapping::DEFAULT_SHELL,
          full_name: person.display_name
        )
      end
      mapping.save! if mapping.changed?

      AuditEvent.record!(actor: "bootstrap", action: "device.register", target: device_id, result: "success",
                         metadata: { person_email: email, posix_username: mapping.username })
      puts "Registered device #{device_id} for #{email} (state=active)."
      puts "POSIX mapping: #{mapping.username} uid=#{mapping.uid} home=#{mapping.home} shell=#{mapping.shell}"
    end
  end
end
