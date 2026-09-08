class CreateIssuedLeases < ActiveRecord::Migration[8.1]
  def change
    create_table :issued_leases do |t|
      t.string :subject_id, null: false
      t.string :device_id, null: false
      # The issuer owns the epoch: monotonic per (subject, device) pair.
      t.integer :revocation_epoch, null: false
      t.text :payload_json, null: false
      t.text :signature_hex, null: false

      t.timestamps
    end
    add_index :issued_leases, [:subject_id, :device_id, :revocation_epoch],
              unique: true, name: "idx_issued_leases_subject_device_epoch"
  end
end
