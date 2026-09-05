# Rails / OIDC composition spike

Run locally with mise-managed Ruby 4 and a resolved, locked dependency bundle.
Use fake identities, isolated development data, and ephemeral keys. No production
server or host PAM changes. Containers are not required for initial development.

From the repository root:

```sh
mise run p0:install
mise run p0:smoke
mise run db:up
mise run p0:protocol
```

The smoke check loads the selected dependencies together and checks a basic Phlex
render. It does not boot a configured issuer or verify RubyUI assets/components.

`p0:protocol` boots a fake-identity Rails issuer in process and uses a temporary
PostgreSQL schema, removed on normal exit. It includes lab discovery and device
denial adapters plus durable refresh-family and person-enabled state.
`mise run p0:protocol:raw` reproduces discovery and missing device-denial failures.
`mise run p0:lifecycle:gates` includes the same family gates now enabled by default.
`mise run p0:lifecycle:raw` reproduces the original unadapted refresh-family failures
alongside discovery/device-denial gaps and intentionally exits nonzero.
See [results and boundaries](../../docs/p0/protocol-experiment.md).

Required assertions before selecting the dependency combination:

- Discovery advertises the supported flow and exact stable issuer.
- Code flow enforces PKCE S256 and exact redirect matching; implicit/password
  grants are unavailable.
- Device authorization handles pending, expiry, denial, polling slowdown, and
  one-time redemption; the future OMA-ID enrollment client must consume the same
  contract in a separate end-to-end test.
- ID token verification rejects wrong issuer/audience/algorithm/nonce, expired
  tokens and unknown keys; UserInfo returns the matching immutable subject.
- Refresh rotation/replay and disablement behave as specified; signing-key
  overlap works without accepting retired keys indefinitely.
- Enrollment, device-service, and app clients cannot exchange each other's authority.

Dependency resolution or source inspection alone passes none of these assertions.
Record missing extension hooks as compatibility findings before writing adapters.
