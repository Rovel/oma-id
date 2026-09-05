# ADR-0003: Refresh replay needs durable family state

Status: implemented and tested in the P0 lab. Independent review and production
directory, authorization and operational integration remain required.

The pinned Doorkeeper bundle with immediate refresh revocation rejects a consumed
refresh token, but does not invalidate its descendants after replay. The two
acceptance tests in `lifecycle_cases.rb` reproduce this with `mise run p0:lifecycle:raw`.
Both now pass with the lab adapter and run in the default protocol suite.

Implemented lab decision: give each independent authorization a durable family
identity, bound to the client and immutable person. Persist ancestry and consumed
token references with appropriate secret protection. Serialize refresh, replay
revocation, and person disablement against the same durable authorization state.
Revalidate inside the transaction before issuing credentials. Replaying a consumed
refresh must invalidate the family and its live descendants; unrelated families
must survive. Authenticate and bind the requesting client before allowing a replay
request to revoke anything, so wrong-client probes cannot revoke another client.

Do not infer ancestry from matching person/client/scope or timestamps, and do not
use process memory as the authoritative family store. A controller precheck alone
cannot prove safety against concurrent refresh and disablement.

Executed tests: parent and older-ancestor replay, descendant access/refresh denial,
wrong-client replay, independent-family isolation, concurrent double refresh,
refresh-vs-disable race, process restart, transaction failure, and durable audit.
The adapter preserves the library's token issuance and cryptography. No upstream
submission or protocol requirement exception is authorized by this ADR.

## Lab implementation boundary

`tests/interop/family_lifecycle.rb` stores person enabled state, client/person-bound
families, parent-linked memberships, consumption timestamps, and audit events in
PostgreSQL. Foreign keys and unique token/parent indexes prevent dangling references
and multiple children for one consumed token. The existing gem stores access,
refresh and grant secrets using its hashing configuration; family/audit records
contain IDs, not bearer secrets.

The person row is the common `FOR UPDATE` lock, acquired before grant/token locks.
Initial token issuance, refresh, family revocation, code/device consent and
disablement use it. Issuance, response serialization, ancestry and audit writes
share a transaction. An audit failure aborts the operation. Expected device polling
errors are handled inside the transaction so polling and expiry state persist.

Consumed token records remain available for detecting older-ancestor replay.
Replay invalidates only the bound family after upstream client authentication.
The revocation endpoint also revokes a family when given a consumed ancestor.
Unknown/untracked refresh credentials fail closed rather than inventing ancestry.

This serializes all families belonging to the lab person, intentionally trading
throughput for a simple lock order. It is not a production directory, multitenant
isolation design, immutable audit store, or retention policy. Production migration
needs an explicit decision for existing untracked refresh credentials, audit export,
and consumed-token retention. The P0 harness creates a fresh disposable schema and
has no production migration path. Do not copy fake-authentication or disabled-CSRF
settings into the product.
