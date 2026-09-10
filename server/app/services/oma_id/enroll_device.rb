# frozen_string_literal: true

module OmaId
  # Enroll one device for one person (plan §7): create the Device record and
  # the durable POSIX mapping (§8.4, allocated by the server). Shared by the
  # P3-a admin acceptance path and the P2 technician pre-provisioning rake
  # task, so both paths provision identically. Idempotent on device_id;
  # refuses to re-bind an existing device to a different person or key.
  class EnrollDevice
    class EnrollError < StandardError; end

    def self.call!(person:, device_id:, public_key_hex:)
      new(person:, device_id:, public_key_hex:).call!
    end

    def initialize(person:, device_id:, public_key_hex:)
      @person = person
      @device_id = device_id.to_s.strip.downcase
      @public_key_hex = public_key_hex.to_s.strip.downcase
    end

    def call!
      raise EnrollError, "no person given" unless @person
      unless @public_key_hex.match?(/\A[0-9a-f]{64}\z/)
        raise EnrollError, "public_key_hex must be 64 hex chars"
      end

      device = Device.find_or_initialize_by(device_id: @device_id)
      if device.persisted?
        if device.person_id != @person.id || device.public_key_hex != @public_key_hex
          raise EnrollError, "device #{@device_id} already exists with a different binding"
        end
        return device if device.active?

        device.update!(state: "active")
        return device
      end

      device.update!(person: @person, public_key_hex: @public_key_hex, state: "active")

      # §8.4: durable POSIX mapping, allocated by the server at provisioning.
      mapping = PosixIdentityMapping.find_or_create_by!(person: @person) do |m|
        username = PosixIdentityMapping.derive_username(@person.primary_email) ||
                   raise(EnrollError, "cannot derive a safe POSIX username")
        uid = PosixIdentityMapping.allocate_uid!
        m.assign_attributes(
          username:, uid:, gid: uid, # primary group matches the UID (user-private groups)
          home: "/home/#{username}", shell: PosixIdentityMapping::DEFAULT_SHELL,
          full_name: @person.display_name
        )
      end
      mapping.save! if mapping.changed?

      device
    end
  end
end
