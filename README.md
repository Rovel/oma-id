# OMA-ID

A self-hosted Rails identity provider and management control plane for
organization-owned Omarchy workstations, with a native Rust endpoint agent.

The selected native-login direction is an OMA-ID-owned Rust agent with a thin
PAM client and provisioned local Unix accounts. See
`docs/adr/0004-owned-omarchy-login-stack.md`; authd is retained only as P0
comparison evidence.
The Rails UI will use Phlex and RubyUI, as recorded in [ADR-0002](docs/adr/0002-phlex-ruby-ui.md).

**Status: P0 discovery in progress. No deployable IAM server or managed login yet.**
The [project plan](oma-id_plan.md) defines scope and release gates.

Start with the [P0 findings and next steps](docs/p0/README.md),
[trust model](docs/security/threat-model.md), and
[login experiment procedure](tests/vm/README.md).

## Baseline discovery

Python 3 and outbound HTTPS are needed to refresh upstream source observations:

```sh
python3 scripts/capture-baseline.py
```

This downloads source archives into ignored `.cache/p0/` and records immutable
commits, archive digests, and gem metadata in `docs/p0/baseline.json`. Review the
diff before adopting a new baseline. It neither installs nor executes upstream
code. Branch snapshots and latest gem releases are separate observations, not a
tested dependency set. Preserve a resulting Bundler lockfile when the protocol
spike resolves successfully.

Initial Rails development uses local mise-managed Ruby 4.0.6. PostgreSQL runs
in Docker Compose with a named volume. The existing Node selection is preserved. Use `mise exec -- ruby -v`
to verify the selected runtime. Rails/gem compatibility and Arch/ISO pins remain
subject to P0.

Check the initial dependency bundle with `mise run p0:install` followed by
`mise run p0:smoke`. This verifies loading/rendering only, not protocol behavior.

## Local database

```sh
docker compose up -d --wait postgres
docker compose exec postgres psql -U oma_id -d oma_id_development
docker compose stop
```

PostgreSQL is available at `127.0.0.1:5432`, with development user `oma_id`,
password `oma_id_local_only`, and database `oma_id_development`. `.env.example`
documents optional overrides and the future Rails `DATABASE_URL`; Rails does not
yet exist. If overriding the password/port, update the connection URL too.

The `postgres_data` named volume survives container recreation and `compose down`.
`compose down --volumes` deletes the database; use only for an intentional reset.
Changing the initialization password does not change an existing database's
password. This local superuser setup is not a production deployment.

PostgreSQL 18 uses the volume mount at `/var/lib/postgresql`, following the
[official image documentation](https://github.com/docker-library/docs/blob/master/postgres/README.md).
