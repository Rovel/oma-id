Rails.application.routes.draw do
  resource :session
  resources :passwords, param: :token
  # Public enrollment metadata (oma-id_plan.md §11.4): protocol versions,
  # canonical issuer, enrollment methods, organization display information.
  # No secrets or executable content. This is the P0 consumer-path endpoint
  # the disposable Omarchy live environment fetches during the hookup test.
  get "/.well-known/oma-enrollment", to: "enrollment_metadata#show", as: :enrollment_metadata

  # Lab lease issuance (bearer-gated; see the controller for the P3 stand-in
  # boundary). Namespace-scoped so CSRF protection does not apply to this
  # token-authenticated JSON API.
  namespace :api do
    namespace :v1 do
      post "device/leases", to: "device_leases#create"
      post "device/check-ins", to: "device_check_ins#create"
      # P3-a enrollment transaction, device side (see the controller).
      # Hyphenated paths, matching the existing API shape (device/check-ins).
      post "enrollment-requests", to: "enrollment_requests#create"
      get "enrollment-requests/:id", to: "enrollment_requests#show", as: :enrollment_request
    end
  end

  # Identity front. Server-rendered Phlex; requires authentication (P1-a).
  root "pages#home"

  # P3-a administrator enrollment review (plan §7.2): pending device
  # requests, admin acceptance bound to a person, rejection, lifecycle clear.
  resources :enrollment_requests, only: %i[index destroy] do
    member { post :accept; post :reject }
  end

  # Admin directory management (plan §21): people + devices + password
  # reset. Role-gated (owner / identity_admin).
  resources :people, only: %i[index new create destroy] do
    member { post :reset_password }
  end
  resources :devices, only: %i[index new create destroy]

  # Authentication (Rails 8 scaffold, adapted to Person + LoginAlias).
  resource :session, only: %i[new create destroy]

  # Reveal health status on /up that returns 200 if the app boots with no
  # exceptions, otherwise 500.
  get "up" => "rails/health#show", as: :rails_health_check
end
