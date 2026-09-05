# ADR-0001: Establish interoperability before the product skeleton

Status: accepted for this foundation, following plan sections 0, 21, and 24.

Keep the repository in P0 until the source baseline and critical feasibility
findings are recorded. Use an isolated minimal Rails issuer with local mise-managed Ruby 4 to evaluate the
Doorkeeper/OIDC/device-grant composition before implementing directory UI.
Rails remains authoritative; a reference IdP only isolates Linux-side failures.

Initial deployment scope is one explicitly modeled organization and one stable
issuer. Multitenant hosting, a new PAM stack, alternate greeter, and arbitrary
remote scripts require separate decisions and acceptance evidence.

Consequence: source capture, experiment tooling, and security documentation land
before the production `server/` and `agent/` implementations. P0 may conclude a
path is blocked; it must not redefine a browser login as desktop interoperability.
