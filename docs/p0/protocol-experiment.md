# P0 Rails protocol experiment

Status: composition and durable family lifecycle experiments executed; P0 remains open.

## Reproduction

Use the root mise configuration and `tests/interop/Gemfile.lock`:

```sh
mise run db:up
mise run p0:install
mise run p0:protocol
mise run p0:protocol:raw
mise run p0:lifecycle:gates
mise run p0:lifecycle:raw
```

The latest adapted protocol suite passed **40 tests / 269 assertions, zero failures,
errors or skips** (`--seed 48655`). It adds algorithm-substitution, discovery-host,
unknown-scope and device-client-scope checks. The lifecycle replay gates
now run by default. Assertion count can vary with which worker wins the tested
refresh/disable race; both outcomes must leave no live credentials.

`p0:lifecycle:raw` preserves the original failures: 25 tests / 137 assertions,
five failures (two discovery, missing proposed device-denial route, two family
replay) and three explicit adapter-only denial skips. The additional family
implementation tests are included only with the adapter. A passing lab suite
does not pass all of P0 or any production gate.

Runtime: local Ruby 4.0.6, Rails 8.1.3.1, Doorkeeper 5.9.6, OIDC 1.10.5,
device-grant 1.0.3, PostgreSQL 18.6. Requests traverse the real Rails middleware,
routes and gem controllers through Rack::Test, in process. No listener or real
TLS exchange is started. JWT validation uses the independent `jwt` library
already present in the bundle, including a public JWKS verification case.

Each process creates a random `oma_p0_<hex>` schema in the local development
database, uses the installed gems' migration templates there, and removes that
schema at normal exit, including assertion failures. It never migrates public
application tables. An abrupt process kill can leave the temporary schema behind;
inspect and remove only that run's schema when cleaning up. The Rails root is a
temporary directory, signing/session keys are ephemeral, and request logging is
disabled to avoid persisting credentials. `DATABASE_URL` is deliberately ignored;
only local `POSTGRES_PORT` and `POSTGRES_PASSWORD` connection overrides are accepted.
`OMA_P0_EXISTING_SCHEMA` is reserved for the fresh-process test: it validates the
random lab schema name and attaches without migrating or removing it. The parent
sends the schema and fake refresh credential over stdin, not process arguments
or files. New connections inherit the same schema from pool configuration.

## Executed results

| Surface | Result |
|---|---|
| Device authorization and fake-person approval | Access, refresh and signed ID tokens issued |
| ID token → UserInfo | Matching immutable fake-person subject |
| Pending / fast polling / expiry | `authorization_pending`, `slow_down`, `expired_token` |
| Sequential device-code replay / wrong client / unknown client | Rejected |
| ID token wrong issuer, audience, key, expiry | Verifier rejects |
| Published JWKS | Validates ID token; no RSA private exponent |
| Refresh rotation / replay of consumed refresh token | New refresh issued; consumed token rejected |
| Authorization code + PKCE S256 | Correct verifier succeeds; wrong verifier/reused code rejected |
| State and nonce | Authorization state and signed nonce preserved |
| Missing PKCE / plain PKCE / changed redirect suffix | Rejected with no issued code |
| Password / implicit grants | Unavailable |
| Raw discovery | Wrong device grant identifier; device endpoint missing |
| Discovery with lab adapter | Both metadata acceptance cases pass |
| Code-flow denial | `access_denied`, correct state/redirect, no credentials issued |
| Device denial with lab adapter | Terminal denial, no later approval, expiry, client isolation |
| Durable fake-person disablement | Existing token access/refresh, approved device redemption and new human authorization blocked |
| Refresh revocation endpoint | Refresh and UserInfo rejected; wrong client cannot revoke |
| Signing-key rotation | New `kid`; old/new keys validate during overlap; fresh JWKS rejects retired key |
| Cached JWKS and already-issued ID tokens | Still validate while unexpired; no instant remote invalidation claim |
| Refresh-family replay gate | Pass with adapter: descendants rejected; raw mode still reproduces failures |
| Family/client isolation | Same-person/client independent grants survive; wrong client/secret cannot revoke a victim family |
| Concurrent double refresh | One issuance, then replay rejection and family revocation |
| Refresh versus disablement | Both workers observed contending on PostgreSQL lock; no live credentials remain |
| Fresh-process ancestor replay | Child process loads persisted ancestry and revokes descendants |
| Audit-write failure | Issuance/consumption or replay revocation rolls back; retry succeeds |
| Secret storage | Gem hashing enabled; family audit contains only references |

## Findings and composition decision

**F01:** Raw discovery advertises `device_code` in `grant_types_supported`.
RFC 8628 section 4 specifies the full device-grant URI. **F02:** Raw discovery
does not expose `device_authorization_endpoint`. That field is optional in the
RFC. It was required by the previously intended authd broker path and remains a
useful standards-correctness check for OMA-ID enrollment clients.

As comparative history, at authd commit `e64cf73a18e600ac7995fe1d96433ce188d43488`,
`authd-oidc-brokers/internal/broker/broker.go:961` rejects the device login mode
when `session.oidcServer.Endpoint().DeviceAuthURL` is empty. This is source
evidence, not an executed interoperability test or a current OMA-ID agent
requirement. ADR-0004 supersedes authd as the selected runtime path.

`tests/interop/discovery_controller.rb` subclasses the library controller through
its routing extension point. It changes only those two discovery fields when
device flow is enabled, using the fixed lab issuer. Installed gems and cryptographic
implementations remain unchanged. Keep this as an explicit P0 adapter until a maintained
upstream solution or reviewed application adapter is selected. No upstream
submission has been made.

**F03:** The installed device-grant controller supplies approval but no denial
action. The lab proposes `DELETE /oauth/device` with the existing user code for
this experiment; that HTTP route is an application choice, not an RFC-mandated
route. `device_lifecycle_controllers.rb` records a terminal `denied_at` on the
pending grant and returns `access_denied` to its matching client until expiry.
Approval and denial lock the grant. Unknown or already-approved user codes cannot
be denied, and a disabled fake person cannot act. This is not a production consent
screen or an independent authorization policy.

**F04:** The raw bundle rejects a consumed refresh token without revoking its
family. [ADR-0003](../adr/0003-refresh-family-replay.md) records the implemented lab
adapter and its limitations. A dedicated PostgreSQL family/member model preserves
ancestry without accepting client-supplied family IDs. A person-row lock serializes
exchange, consent, replay, revocation and disablement. Successful token issuance,
response serialization, membership and audit commit together; operational errors
roll them back. No process-local family cache is authoritative.

Replay of a consumed ancestor revokes live family tokens and records one durable
event. Repeated replay is idempotent, and independent families survive. The normal
revocation endpoint also invalidates descendants when given a consumed ancestor.
Consumed records are retained in this lab; production retention/migration policy
is still required. Existing untracked refresh credentials are rejected by the
adapter, not silently assigned a new family.

Reference: [RFC 8628 discovery metadata](https://www.rfc-editor.org/rfc/rfc8628.html#section-4).

## Deliberate limitations and next step

The owner is a fixed fake identity; consent is automatically accepted for code
flow, and CSRF is disabled in this in-process harness. Browser sign-in, passkeys,
MFA, consent UX, CSRF protection, Phlex/RubyUI application pages, and TLS remain
untested. These settings must not become production defaults.

Refresh revocation uses the upstream documented immediate-revocation schema
option (no `previous_refresh_token` column). The explicit `Lab.disable_person!`
operation locks and disables the persisted lab person, revokes their families,
tokens and code grants, deletes approved device grants, and records local audit
events in one transaction. This is application behavior, not automatic gem
disablement. It has no production directory/MFA integration, organizational
authorization, external audit export, or outbox delivery yet.
Likewise, one fast-poll rejection does not establish persistent slowdown behavior.

Remaining protocol evidence: concurrent device/code redemption and approval races,
scope/client-role confusion, persistent slowdown, algorithm/nonce substitution,
discovery host tampering, production signing-key custody/cache policy, and actual
the enrollment contract. Next close those protocol cases and connect a real
OMA-ID enrollment client in the
separately isolated VM experiment. No native
login, offline enforcement, certification, or production gate passes here.
