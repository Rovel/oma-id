# OMA-ID development

Read `oma-id_plan.md` completely before architectural changes. Its section 24 is
the execution contract. Current work is P0; P1 requires recorded baseline findings.

- Rails owns identity. Reference identity providers are disposable test dependencies.
- Use local mise-managed Ruby 4 for Rails development and fake-identity protocol
  experiments. Use Phlex, phlex-rails, and RubyUI for the Rails UI.
- Use Compose PostgreSQL with the named volume for local development data.
  Keep its port bound to localhost; volume deletion requires intentional reset.
- OMA-ID owns a narrow Rust agent plus PAM integration and provisions real local
  users; authd is comparative evidence, not a production dependency. Do not add
  NSS without a recorded requirement and architecture/security review.
- Run OS/PAM/account-provisioning experiments only in disposable containers or VMs. Never
  modify host PAM, disks, accounts, or production device enrollment.
- Never publish upstream messages or PRs without explicit user authorization.
- Keep source observations, design proposals, and executed test evidence distinct.
  A source pin is not compatibility evidence; a container is not a desktop VM.
- Record source revisions, commands, results, failures, and recovery conditions in
  `docs/p0/`. Keep secrets and large downloaded artifacts out of git.
- Do not mark login/offline gates passed without testing the actual consumer paths.
- Preserve separate human, device, policy-signing, release-signing, and recovery trust.
