# frozen_string_literal: true

# Administrator directory management (plan §5.1, §21): create/remove people,
# and trigger password resets. Passwords are local (§10: never synced). A
# reset generates a password shown ONCE on an ephemeral render (the same
# bootstrap_owner discipline: never stored in logs, never sent anywhere) and
# terminates the person's sessions. Removing a person is refused while they
# have enrolled devices — remove those first (§8.4 integrity: provisioned
# local accounts and issued leases must not be orphaned silently).
class PeopleController < ApplicationController
  include AdminRequired

  PER_PAGE = 10

  before_action :set_person, only: %i[destroy reset_password]

  def index
    scope = Person.order(:created_at)
    scope = scope.joins(:login_aliases).where("login_aliases.email_address LIKE ?", "%#{sanitized_search}%")
                 .or(scope.where("display_name LIKE ?", "%#{sanitized_search}%")) if search?
    @total_count = scope.count
    @page = [ params.fetch(:page, 1).to_i, 1 ].max
    @per_page = PER_PAGE
    @people = scope.offset((@page - 1) * @per_page).limit(@per_page).includes(:login_aliases)
    render Views::People::Index.new(people: @people, search: params[:search].to_s,
                                    page: @page, per_page: @per_page, total_count: @total_count),
           layout: "application"
  end

  def new
    render Views::People::New.new(person: Person.new), layout: "application"
  end

  def create
    password = params[:password].presence || SecureRandom.base58(20)
    generated = params[:password].blank?
    person = nil
    ActiveRecord::Base.transaction do
      person = Person.create!(display_name: params[:display_name].to_s.strip,
                              role: params[:role].to_s,
                              password:, password_confirmation: password)
      person.login_aliases.create!(email_address: params[:email_address].to_s)
    end
    AuditEvent.record!(actor: actor_name, action: "person.create", target: person.primary_email,
                       result: "success", metadata: { role: person.role, generated_password: generated })
    if generated
      render Views::People::PasswordReset.new(person:, password:, action_label: "created"),
             layout: "application"
    else
      redirect_to people_path, notice: "Person #{person.primary_email} created."
    end
  rescue ActiveRecord::RecordInvalid => e
    redirect_to new_person_path, alert: "Refused: #{e.message.split(": ").last}"
  end

  def destroy
    if @person.devices.exists?
      redirect_to people_path,
                  alert: "Refused: #{@person.primary_email} has enrolled devices. Remove those first (§8.4)."
      return
    end
    mapping = PosixIdentityMapping.find_by(person: @person)
    ActiveRecord::Base.transaction do
      @person.destroy!
      AuditEvent.record!(actor: actor_name, action: "person.destroy", target: @person.primary_email,
                         result: "success",
                         metadata: { posix_username: mapping&.username, posix_uid: mapping&.uid,
                                     note: "mapping removed; any local accounts remain on the machines" })
    end
    redirect_to people_path, notice: "Person removed."
  end

  # Admin-triggered password reset (§10: local passwords; §16 audited). The
  # generated password renders once and is never persisted anywhere except
  # its bcrypt digest.
  def reset_password
    password = SecureRandom.base58(20)
    @person.update!(password:, password_confirmation: password)
    @person.sessions.destroy_all
    AuditEvent.record!(actor: actor_name, action: "person.password_reset",
                       target: @person.primary_email, result: "success")
    render Views::People::PasswordReset.new(person: @person, password:, action_label: "reset"),
           layout: "application"
  end

  private

  def set_person
    @person = Person.find(params[:id])
  end

  def search?
    params[:search].present?
  end

  def sanitized_search
    "%#{params[:search].to_s.gsub(/[\\%_]/) { |c| "\\#{c}" }}%"
  end
end
