Rails.application.routes.draw do
  # Public enrollment metadata (oma-id_plan.md §11.4): protocol versions,
  # canonical issuer, enrollment methods, organization display information.
  # No secrets or executable content. This is the P0 consumer-path endpoint
  # the disposable Omarchy live environment fetches during the hookup test.
  get "/.well-known/oma-enrollment", to: "enrollment_metadata#show", as: :enrollment_metadata

  # Identity front. Server-rendered Phlex; locally served assets only.
  root "pages#home"

  # Reveal health status on /up that returns 200 if the app boots with no
  # exceptions, otherwise 500.
  get "up" => "rails/health#show", as: :rails_health_check
end
