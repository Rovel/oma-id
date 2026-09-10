# frozen_string_literal: true

# P3-a enrollment transaction (plan §7.2, §7.3): a device asks to enroll by
# posting its key and hardware identity; the request sits in `pending` with
# no organizational access until an administrator accepts it in the trusted
# browser (the unattended/admin-approval enrollment mode, §6.3). Key
# possession is proven separately by a device-signed status poll (§7.2 step
# 4, minimal form) before acceptance is allowed.
class CreateEnrollmentRequests < ActiveRecord::Migration[8.1]
  def change
    create_table :enrollment_requests do |t|
      # The device public key is the enrollment identity claim (§7.2 step 1);
      # re-posting the same key returns the same pending request.
      t.string :public_key_hex, null: false
      t.string :state, null: false, default: "pending"
      t.string :nonce, null: false

      # Minimally necessary device details (§7.2 step 1) — hardware identity
      # the administrator reviews when deciding.
      t.string :device_name
      t.string :manufacturer
      t.string :model
      t.string :serial_number
      t.string :machine_id
      t.string :requested_device_id

      # Set when a device-signed status poll verifies possession (§7.2 step 4).
      t.datetime :key_possession_verified_at

      t.references :person, null: true
      t.references :device, null: true

      t.timestamps
    end
    add_index :enrollment_requests, :public_key_hex, unique: true
    add_index :enrollment_requests, :state
  end
end
