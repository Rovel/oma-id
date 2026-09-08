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

ActiveRecord::Schema[8.1].define(version: 2026_09_08_023912) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"

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

  create_table "organizations", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "issuer", null: false
    t.string "name", null: false
    t.string "support_email", null: false
    t.datetime "updated_at", null: false
    t.index ["issuer"], name: "index_organizations_on_issuer", unique: true
  end
end
