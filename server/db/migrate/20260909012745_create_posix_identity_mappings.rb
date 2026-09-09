class CreatePosixIdentityMappings < ActiveRecord::Migration[8.1]
  def change
    create_table :posix_identity_mappings do |t|
      t.references :person, null: false, foreign_key: true
      t.string :username, null: false
      t.integer :uid, null: false
      t.integer :gid, null: false
      t.string :home, null: false
      t.string :shell, null: false
      t.string :full_name

      t.timestamps
    end
    add_index :posix_identity_mappings, :username, unique: true
    add_index :posix_identity_mappings, :uid, unique: true
    add_index :posix_identity_mappings, :gid, unique: true
  end
end
