class CreateLoginAliases < ActiveRecord::Migration[8.1]
  def change
    create_table :login_aliases do |t|
      t.references :person, null: false, foreign_key: true
      # §5.1: the email is a login alias, never the identity. Changing or
      # removing an alias must not create a new person or transfer access.
      t.string :email_address, null: false

      t.timestamps
    end
    add_index :login_aliases, :email_address, unique: true
  end
end
