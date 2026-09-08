class CreateAuditEvents < ActiveRecord::Migration[8.1]
  def change
    create_table :audit_events do |t|
      # §16: actor, action, target, result, metadata (secrets redacted).
      # P1-a: the actor is the person (or "bootstrap"/"anonymous" for
      # pre-authentication events).
      t.string :actor, null: false
      t.string :action, null: false
      t.string :target
      t.string :result, null: false
      t.jsonb :metadata, default: {}

      t.timestamps
    end
    add_index :audit_events, :action
    add_index :audit_events, :created_at
  end
end
