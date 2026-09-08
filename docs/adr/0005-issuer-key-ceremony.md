# ADR-0005: Issuer key ceremony and rotation for offline leases

Status: accepted on 2026-09-08 by the project owner.

## Context

Offline leases (plan §9.1) are ed25519-signed by the Rails issuer and
verified by the endpoint agent against a pinned issuer key. Until now the
agent pinned exactly one key (a hex argument), the Rails side derived its
signing key from a lab seed with an insecure default, and nothing recorded
how keys are generated, distributed, rotated, or revoked. Plan §5.3 requires
lease-signing keys to be a separate key purpose (never shared with OIDC
signing, device CA, policy signing, or recovery wrapping), §17.1 forbids
production signing roots in the repository or baked images, and §13/§18
require rehearsed rotation and compromise response.

## Decision

**1. One key pair per purpose, per deployment.** The lease-signing key pair
is generated once per OMA-ID deployment and used only for offline lease
signing. Generation happens on the server (the lease key signs frequently
and is an online key by nature — unlike the offline CA root, which follows
the device-CA slice). Production generation uses a CSPRNG (Ruby `SecureRandom`
/ Rust `rand`); fixed lab seeds are compile/test fixtures only.

**2. Key identity is `key_id` = SHA-256 of the raw public key**, hex-encoded.
The id is derived, never chosen, so two keys cannot collide or be confused,
and the id can be recomputed from public material at any time.

**3. Private key storage.** The private key lives in the server's secret
store: Rails credentials (`rails credentials:edit`) or an injected
environment variable in production; a lab seed may be supplied via
`OMA_ID_ISSUER_SEED` **only** when `RAILS_ENV` is development or test. In
production the issuer **refuses to sign** with a lab/missing key — fail
closed. The private key never enters the database, the repository, the
lease response, or any log.

**4. Agent pinning is a key SET with explicit states.** The agent pins a
JSON key-set file instead of a single hex key:

```json
{
  "version": 1,
  "keys": [
    { "key_id": "<sha256-hex>", "public_key_hex": "<ed25519>", "state": "active" },
    { "key_id": "<sha256-hex>", "public_key_hex": "<ed25519>", "state": "retiring" }
  ]
}
```

- `active` — signs new leases (exactly one active key at a time).
- `retiring` — still verifies existing leases during the overlap window.
- `revoked` — never verifies; its presence records the revocation.

A lease carries the `key_id` that signed it; verification selects the
matching key from the pinned set. The single-key `--issuer-key` argument
remains as a compatibility shorthand (an implicit unnamed single-key set).

**5. Rotation has an overlap window.** The operator generates a new key,
adds it to the key set as `active`, flips the old key to `retiring`, and
after every device has refreshed its lease (or after the maximum lease
validity — 24h by §9.2, whichever is shorter) removes the retiring entry.
During the overlap both signatures verify.

**6. Compromise response.** The compromised key's entry becomes `revoked`
in the key set, the deployment's revocation epoch is bumped and new leases
are issued from the active key. Devices receive the updated key set through
their management channel; because leases are short-lived and epoch-checked,
the revoked key cannot mint an acceptable lease once devices refresh.
Detection and fleet distribution of the new key set are management-plane
work (P4 check-in), recorded here as the required path.

**7. Public keys are distributable; private keys are not.** The Rails
server records `IssuerKey` rows (key_id, public key, purpose `lease_signing`,
state) for rotation metadata and audit. Private material stays in the secret
store.

## Consequences

- The agent fails closed on an unknown `key_id` (not in the pinned set) —
  a lease signed by a never-pinned or revoked key is `Deny(NotAuthorized)`
  through the opaque denial path.
- The store file format gains `key_id` per lease (version 2); version 1
  files (single implicit key) remain readable.
- Rails must be configured with real key material to sign in production;
  the lab default seed fails closed outside development/test.
- Key-set distribution to agents is initially manual (the lab flow) and
  moves to the P4 check-in channel; until then agents are pinned by the
  operator at provisioning.
- A lease signed by a retiring key remains valid until expiry — the
  offline window (§9.2) bounds the exposure, as designed.

## Alternatives considered

- **Single key, no rotation**: simplest, but §13/§18 require rehearsed
  rotation and compromise response; a compromised key would brick the fleet
  or force unverifiable leases.
- **PKI/chain-signed keys (step-ca)**: right for the device CA slice
  (§7.4); over-engineering for the lease key whose trust root is the
  deployment itself. Revisit if lease-signing authority must be delegated.
- **Rails-held key registry with on-demand distribution**: couples agent
  boot to server availability; rejected for offline-first operation (§9).
