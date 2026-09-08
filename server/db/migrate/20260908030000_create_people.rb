class CreatePeople < ActiveRecord::Migration[8.1]
  def change
    create_table :people do |t|
      t.string :display_name, null: false
      # §5.2 minimal roles (P1-a boundary): role on the person is acceptable
      # for the single-organization deployment (ADR-0004); the full
      # RoleAssignment model (§16) arrives with multi-scope work.
      t.integer :role, null: false, default: 2 # :employee
      # P1-a credential boundary: the password digest lives on the person.
      # P1-b moves credentials to a dedicated table and adds WebAuthn
      # passkeys as the preferred method (§5.1).
      t.string :password_digest, null: false

      t.timestamps
    end
  end
end
