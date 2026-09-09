# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_09_08_131453) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"

  create_table "audit_events", force: :cascade do |t|
    t.string "action", null: false
    t.string "actor", null: false
    t.datetime "created_at", null: false
    t.jsonb "metadata", default: {}
    t.string "result", null: false
    t.string "target"
    t.datetime "updated_at", null: false
    t.index ["action"], name: "index_audit_events_on_action"
    t.index ["created_at"], name: "index_audit_events_on_created_at"
  end

  create_table "devices", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "device_id", null: false
    t.datetime "last_check_in_at"
    t.bigint "person_id", null: false
    t.string "public_key_hex", null: false
    t.string "state", default: "active", null: false
    t.datetime "updated_at", null: false
    t.index ["device_id"], name: "index_devices_on_device_id", unique: true
    t.index ["person_id"], name: "index_devices_on_person_id"
    t.index ["state"], name: "index_devices_on_state"
  end

  create_table "issued_leases", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "device_id", null: false
    t.text "payload_json", null: false
    t.integer "revocation_epoch", null: false
    t.text "signature_hex", null: false
    t.string "subject_id", null: false
    t.datetime "updated_at", null: false
    t.index ["subject_id", "device_id", "revocation_epoch"], name: "idx_issued_leases_subject_device_epoch", unique: true
  end

  create_table "issuer_keys", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "key_id", null: false
    t.string "public_key_hex", null: false
    t.string "purpose", null: false
    t.string "state", null: false
    t.datetime "updated_at", null: false
    t.index ["purpose", "key_id"], name: "index_issuer_keys_on_purpose_and_key_id", unique: true
    t.index ["purpose", "state"], name: "index_issuer_keys_on_purpose_and_state"
  end

  create_table "login_aliases", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "email_address", null: false
    t.bigint "person_id", null: false
    t.datetime "updated_at", null: false
    t.index ["email_address"], name: "index_login_aliases_on_email_address", unique: true
    t.index ["person_id"], name: "index_login_aliases_on_person_id"
  end

  create_table "organizations", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "issuer", null: false
    t.string "name", null: false
    t.string "support_email", null: false
    t.datetime "updated_at", null: false
    t.index ["issuer"], name: "index_organizations_on_issuer", unique: true
  end

  create_table "people", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "display_name", null: false
    t.string "password_digest", null: false
    t.integer "role", default: 2, null: false
    t.datetime "updated_at", null: false
  end

  create_table "sessions", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "ip_address"
    t.bigint "person_id", null: false
    t.datetime "updated_at", null: false
    t.string "user_agent"
    t.index ["person_id"], name: "index_sessions_on_person_id"
  end

  add_foreign_key "devices", "people"
  add_foreign_key "login_aliases", "people"
  add_foreign_key "sessions", "people"
end
