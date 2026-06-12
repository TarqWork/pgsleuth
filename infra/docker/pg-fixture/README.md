# pgsleuth dev Postgres fixture

Three-node streaming-replication cluster with `pg_stat_statements` and
`auto_explain` enabled. Used for local development and (forthcoming)
Tier 1 collector integration tests.

This fixture is **separate** from `infra/docker/docker-compose.yml`,
which is the eBPF feasibility rig. Different concerns; running one does
not start the other.

## Quick start

```bash
make fixture-up           # bring it up (detached)
make fixture-status       # confirm all three are healthy
make fixture-psql         # open psql on the primary
make fixture-down         # stop containers (volumes persist)
make fixture-reset        # stop + drop volumes — next up re-bootstraps
```

`make dev` also calls `fixture-up` as its last step, so a fresh checkout
is one command from a usable rig.

## Topology

```
       ┌────────────────────────┐
       │ pg-primary             │  postgres://postgres@localhost:5432/postgres
       │ port 5432              │
       │ wal_level = replica    │
       │ pg_stat_statements     │
       │ auto_explain           │
       └─────┬──────────────────┘
             │ streaming (replication slots: replica_1, replica_2)
   ┌─────────┴──────────┐
   ▼                    ▼
┌──────────────┐  ┌──────────────┐
│ pg-replica-1 │  │ pg-replica-2 │
│ port 5433    │  │ port 5434    │
│ hot standby  │  │ hot standby  │
└──────────────┘  └──────────────┘
```

All three containers share the `pg-fixture-net` network and run
`postgres:17-bookworm`.

## Connection strings

| Role             | Connection                                                       |
|------------------|------------------------------------------------------------------|
| superuser (writes) | `postgres://postgres@localhost:5432/postgres`                  |
| replica-1 (RO)   | `postgres://postgres@localhost:5433/postgres`                    |
| replica-2 (RO)   | `postgres://postgres@localhost:5434/postgres`                    |
| **agent** (RO)   | `postgres://pgsleuth_agent:pgsleuth@localhost:5432/postgres`     |

The `pgsleuth_agent` role is the role the agent is expected to use —
it has `pg_monitor` + `pg_read_all_stats` so it can see everything
`pg_stat_*` exposes without write privileges. The architecture invariant
(brain never touches the DB; agent is read-only) is enforced at the role
level by this fixture.

Passwords here are intentionally weak. **This fixture is never to be
exposed beyond localhost.**

## Pointing the agent at the fixture

```bash
# Tier 1 collectors (pg_stat_statements / pg_stat_activity)
pgsleuth-cli --pg-conn postgres://pgsleuth_agent:pgsleuth@localhost:5432/postgres

# eBPF loader (postmaster PID discovery — same db, same role)
pgsleuth-ebpf-loader --pg-conn postgres://pgsleuth_agent:pgsleuth@localhost:5432/postgres
```

## Replication mechanics

- The primary's `init-primary.sql` creates the `replicator` role and two
  named physical replication slots (`replica_1`, `replica_2`) at first boot.
- Each replica's `replica-entrypoint.sh` checks whether its `PGDATA` is
  populated. If empty, it `pg_isready`-polls the primary, then
  `pg_basebackup --write-recovery-conf --slot=<slot>` to stream a copy
  and write `standby.signal`, then hands off to the standard Postgres
  entrypoint. Subsequent boots skip the bootstrap.
- `make fixture-reset` drops the named volumes so the next `fixture-up`
  re-runs the bootstrap — useful when you've changed the primary's
  config or `init-primary.sql`.

## Files

- `pg-fixture.compose.yml` — compose for the three services + their volumes/network.
- `pg-fixture/postgresql.primary.conf` — primary's Postgres config (extensions, replication tuning, log shape).
- `pg-fixture/pg_hba.conf` — auth config; trust local, md5 replication. Symmetric on replicas after base backup.
- `pg-fixture/init-primary.sql` — creates `replicator`, replication slots, the `pgsleuth_agent` role.
- `pg-fixture/replica-entrypoint.sh` — first-boot `pg_basebackup` then handoff.

## What this fixture is NOT

- ❌ Not a production reference. Authentication is trust-everywhere on
  localhost. WAL retention is unbounded. Replicas can drift indefinitely
  if disconnected — the slots stop garbage collection.
- ❌ Not a regression target for the eBPF Tier 3 path. That rig is
  `docker-compose.yml` next door.
- ❌ Not a benchmarking fixture. Nothing is tuned for throughput.
