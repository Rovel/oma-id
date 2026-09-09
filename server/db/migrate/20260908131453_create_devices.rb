class CreateDevices < ActiveRecord::Migration[8.1]
  def change
    create_table :devices do |t|
      # §7.4: hardware serials are hints, not identity — the device identity
      # is its key pair; device_id is the server-assigned handle.
      t.string :device_id, null: false
      t.references :person, null: false, foreign_key: true
      # The registered ed25519 public key (hex): check-ins are signed with
      # the matching private key (§7.2 key possession, pre-provisioning mode).
      t.string :public_key_hex, null: false
      t.string :state, null: false, default: "active"
      t.datetime :last_check_in_at

      t.timestamps
    end
    add_index :devices, :device_id, unique: true
    add_index :devices, :state
  end
end
