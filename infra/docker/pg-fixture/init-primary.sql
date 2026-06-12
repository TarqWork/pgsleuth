-- Bootstrap the pgsleuth dev fixture primary.
-- Runs once at first boot via /docker-entrypoint-initdb.d/.

-- Replication user the replicas use for pg_basebackup + streaming. The
-- password is referenced from the replica entrypoint script — bump both
-- together if it changes.
CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'replicator';

-- One physical replication slot per replica. Slots keep WAL around for a
-- disconnected standby, which is exactly what we want for a dev rig
-- where the replicas may be restarted/recreated freely.
SELECT pg_create_physical_replication_slot('replica_1');
SELECT pg_create_physical_replication_slot('replica_2');

-- The extensions the fixture exists to exercise. shared_preload_libraries
-- in postgresql.primary.conf has already loaded the .so; CREATE EXTENSION
-- registers the SQL-level surface.
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Read-only role the agent is expected to use. The agent never writes;
-- handing it the superuser role would be a code smell we don't want to
-- bake into the fixture. The brain doesn't touch the DB at all (see
-- 000-architecture.md).
CREATE ROLE pgsleuth_agent WITH LOGIN PASSWORD 'pgsleuth' IN ROLE pg_read_all_stats;
GRANT pg_monitor TO pgsleuth_agent;
