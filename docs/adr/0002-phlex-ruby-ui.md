# ADR-0002: Phlex and RubyUI for the Rails interface

Status: selected by the project owner, 2026-09-04; runtime compatibility pending.

Use Phlex views/components, `phlex-rails` integration, and `ruby_ui` components
for the Rails application. Keep server-rendered navigation with Turbo/Stimulus
where interaction requires it. Include the UI gems in the P0 dependency spike.

Use application-owned views for login, device approval, and later administration.
Authorization stays in the application boundary, never just component visibility.
Credential and approval pages require CSRF protection, accessible keyboard
interaction, and no third-party asset/CDN requests. Review RubyUI's installation
and asset requirements at the selected version before generating the app.

References: https://www.phlex.fun/ and https://www.rubyui.com/.
