class CreateOrganizations < ActiveRecord::Migration[8.1]
  def change
    create_table :organizations do |t|
      t.string :name, null: false
      # Canonical OIDC/issuer origin. ADR-0004: stable per deployment;
      # display-name changes must never alter it. http:// is permitted in
      # this P0 lab slice only (plan §6.2 requires HTTPS for real enrollment).
      t.string :issuer, null: false
      t.string :support_email, null: false

      t.timestamps
    end
    add_index :organizations, :issuer, unique: true
  end
end
