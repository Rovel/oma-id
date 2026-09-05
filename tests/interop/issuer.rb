# frozen_string_literal: true

# In-process, fake-identity laboratory only. No HTTP listener or production boot path.
ENV["RAILS_ENV"] = "test"
require "rails"
require "active_record/railtie"
require "action_controller/railtie"
require "openssl"
require "securerandom"
require "erb"
require "logger"
require "tmpdir"
Bundler.require

module Lab
  ISSUER = "https://issuer.oma.test"
  KEY = OpenSSL::PKey::RSA.generate(2048)
  PERSON = Struct.new(:id, :subject, :authenticated_at, :enabled).new(1, "lab-person-immutable-001", Time.now.utc, true)
  def PERSON.enabled = Lab::PersonState.find(id).enabled
  def PERSON.enabled=(value)
    Lab::PersonState.find(id).update!(enabled: value)
  end
  class << self
    attr_accessor :signing_keys

    def disable_person!
      FamilyLifecycle.disable_person!
    end
  end
  self.signing_keys = [KEY.to_pem]

  class Application < Rails::Application
    config.root = Dir.mktmpdir("oma-id-issuer-")
    config.eager_load = false
    config.secret_key_base = SecureRandom.hex(64)
    config.logger = Logger.new(File::NULL)
    config.hosts = ["issuer.oma.test"]
    # Authentication/CSRF UX is outside this in-process protocol experiment.
    config.action_controller.allow_forgery_protection = false
    config.action_dispatch.show_exceptions = :none
    config.active_support.deprecation = :stderr
  end
  at_exit { FileUtils.remove_entry(Application.config.root) if File.exist?(Application.config.root) }
end

Doorkeeper.configure do
  orm :active_record
  resource_owner_authenticator { Lab::PERSON.enabled ? Lab::PERSON : (head :unauthorized) }
  admin_authenticator { head :forbidden }
  grant_flows %w[authorization_code device_code]
  default_scopes :openid
  optional_scopes :profile
  enforce_configured_scopes
  hash_token_secrets unless ENV["OMA_P0_RAW"] == "1"
  force_pkce
  pkce_code_challenge_methods ["S256"]
  use_refresh_token
  access_token_expires_in 300
  skip_authorization { true }
end
Doorkeeper::DeviceAuthorizationGrant.configure do
  device_code_expires_in 600
  device_code_polling_interval 5
end
Doorkeeper::OpenidConnect.configure do
  issuer Lab::ISSUER
  signing_key -> { Lab.signing_keys }
  subject_types_supported [:public]
  subject { |owner, _application| owner.subject }
  resource_owner_from_access_token { |token| Lab::PERSON if token.resource_owner_id == Lab::PERSON.id }
  auth_time_from_resource_owner { |owner| owner.authenticated_at }
  protocol { :https }
end

# Use a unique schema, never application tables. Do not accept DATABASE_URL, which
# could accidentally point at a production application database.
ENV["DATABASE_URL"] = "postgresql://oma_id:#{URI.encode_uri_component(ENV.fetch('POSTGRES_PASSWORD', 'oma_id_local_only'))}@127.0.0.1:#{Integer(ENV.fetch('POSTGRES_PORT', '5432'))}/oma_id_development"
Lab::Application.initialize!
require_relative "discovery_controller"
require_relative "family_lifecycle"
require_relative "device_lifecycle_controllers"
Lab::Application.routes.draw do
  use_doorkeeper do
    skip_controllers :applications, :authorized_applications
    controllers tokens: "lab/tokens" unless ENV["OMA_P0_RAW"] == "1"
    controllers authorizations: "lab/authorizations" unless ENV["OMA_P0_RAW"] == "1"
  end
  use_doorkeeper_openid_connect do
    controllers discovery: "lab/discovery" unless ENV["OMA_P0_RAW"] == "1"
  end
  use_doorkeeper_device_authorization_grant do
    controller device_codes: "lab/device_codes" unless ENV["OMA_P0_RAW"] == "1"
    controller device_authorizations: "lab/device_authorizations" unless ENV["OMA_P0_RAW"] == "1"
  end
  delete "/oauth/device", to: "lab/device_authorizations#deny" unless ENV["OMA_P0_RAW"] == "1"
end

module Lab
  def self.prepare_database!
    connection = ActiveRecord::Base.connection
    reused_schema = ENV["OMA_P0_EXISTING_SCHEMA"]
    raise "Invalid lab schema" if reused_schema && !reused_schema.match?(/\Aoma_p0_[0-9a-f]{24}\z/)
    @schema = reused_schema || "oma_p0_#{SecureRandom.hex(12)}"
    connection.execute("CREATE SCHEMA #{@schema}") unless reused_schema
    # Put the schema in pool configuration, including fresh worker/process
    # connections. A setting on only the main connection is unsafe for concurrency.
    db_config = ActiveRecord::Base.connection_db_config.configuration_hash.merge(schema_search_path: @schema, pool: 8, application_name: @schema)
    ActiveRecord::Base.establish_connection(db_config)
    connection = ActiveRecord::Base.connection
    return if reused_schema # Child probe never migrates or removes the parent's schema.
    at_exit do
      connection.schema_search_path = "public"
      connection.execute("DROP SCHEMA #{@schema} CASCADE")
    end

    # Evaluate the installed gems' migration templates in this disposable schema.
    # No vendored upstream implementation or production migrations are created.
    migration_version = "[8.1]"
    %w[doorkeeper doorkeeper-openid_connect].each do |name|
      relative = name == "doorkeeper" ? "doorkeeper" : "doorkeeper/openid_connect"
      path = File.join(Gem.loaded_specs.fetch(name).full_gem_path,
                       "lib/generators/#{relative}/templates/migration.rb.erb")
      eval(ERB.new(File.read(path)).result(binding), TOPLEVEL_BINDING, path)
    end
    ActiveRecord::Migration.verbose = false
    CreateDoorkeeperTables.migrate(:up)
    CreateDoorkeeperOpenidConnectTables.migrate(:up)
    path = File.join(Gem.loaded_specs.fetch("doorkeeper-device_authorization_grant").full_gem_path,
                     "db/migrate/20200629094624_create_doorkeeper_device_grants.rb")
    load path
    CreateDoorkeeperDeviceGrants.migrate(:up)
    connection.add_column :oauth_device_grants, :denied_at, :datetime
    connection.add_column :oauth_access_grants, :code_challenge, :string
    connection.add_column :oauth_access_grants, :code_challenge_method, :string
    # Select documented immediate refresh revocation, not deferred revocation.
    connection.remove_column :oauth_access_tokens, :previous_refresh_token
    connection.create_table(:lab_people) { |t| t.boolean :enabled, null: false, default: true }
    connection.create_table :lab_token_families do |t|
      t.bigint :person_id, null: false
      t.bigint :application_id, null: false
      t.datetime :revoked_at
      t.timestamps
    end
    connection.create_table :lab_family_members do |t|
      t.bigint :family_id, null: false
      t.bigint :token_id, null: false
      t.bigint :parent_id
      t.datetime :consumed_at
      t.timestamps
    end
    connection.add_index :lab_family_members, :token_id, unique: true
    connection.add_index :lab_family_members, :parent_id, unique: true
    connection.add_index :lab_family_members, :family_id
    connection.create_table :lab_lifecycle_events do |t|
      t.bigint :person_id, null: false
      t.bigint :family_id
      t.bigint :token_id
      t.string :action, null: false
      t.timestamps
    end
    connection.add_foreign_key :lab_token_families, :lab_people, column: :person_id
    connection.add_foreign_key :lab_token_families, :oauth_applications, column: :application_id
    connection.add_foreign_key :lab_family_members, :lab_token_families, column: :family_id
    connection.add_foreign_key :lab_family_members, :oauth_access_tokens, column: :token_id
    connection.add_foreign_key :lab_family_members, :lab_family_members, column: :parent_id
    connection.add_foreign_key :lab_lifecycle_events, :lab_people, column: :person_id
    connection.add_foreign_key :lab_lifecycle_events, :lab_token_families, column: :family_id
    connection.add_foreign_key :lab_lifecycle_events, :oauth_access_tokens, column: :token_id
    PersonState.create!(id: PERSON.id)
  end
end
Lab.prepare_database!
