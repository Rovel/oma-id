class CreateIssuerKeys < ActiveRecord::Migration[8.1]
  def change
    create_table :issuer_keys do |t|
      t.string :key_id, null: false
      t.string :public_key_hex, null: false
      t.string :purpose, null: false
      t.string :state, null: false

      t.timestamps
    end
    add_index :issuer_keys, [:purpose, :key_id], unique: true
    add_index :issuer_keys, [:purpose, :state]
  end
end
