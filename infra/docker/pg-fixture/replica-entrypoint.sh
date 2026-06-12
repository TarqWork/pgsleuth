#!/bin/bash
# Entrypoint for a pgsleuth-fixture replica container.
#
# If PGDATA is empty (first boot of this container's named volume), wait
# for the primary to be ready, run `pg_basebackup` to stream a copy of
# the cluster, then chain to the standard Postgres entrypoint to start
# in standby mode. Subsequent boots see a populated PGDATA and skip
# straight to startup.
#
# Inputs (set by docker-compose):
#   REPLICA_PRIMARY_HOST   hostname of the primary container (e.g. pg-primary)
#   REPLICA_PRIMARY_PORT   port (default 5432)
#   REPLICA_SLOT_NAME      physical replication slot to attach to
#                          (created by init-primary.sql)

set -euo pipefail

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
REPLICA_PRIMARY_HOST="${REPLICA_PRIMARY_HOST:?REPLICA_PRIMARY_HOST is required}"
REPLICA_PRIMARY_PORT="${REPLICA_PRIMARY_PORT:-5432}"
REPLICA_SLOT_NAME="${REPLICA_SLOT_NAME:?REPLICA_SLOT_NAME is required}"

log() { echo "[replica-entrypoint] $*"; }

bootstrap_from_primary() {
    log "PGDATA is empty; waiting for primary $REPLICA_PRIMARY_HOST:$REPLICA_PRIMARY_PORT"
    until PGPASSWORD=replicator pg_isready \
            -h "$REPLICA_PRIMARY_HOST" \
            -p "$REPLICA_PRIMARY_PORT" \
            -U replicator >/dev/null 2>&1; do
        log "primary not ready yet, retrying in 2s"
        sleep 2
    done
    log "primary up; running pg_basebackup into $PGDATA (slot=$REPLICA_SLOT_NAME)"
    PGPASSWORD=replicator pg_basebackup \
        --host="$REPLICA_PRIMARY_HOST" \
        --port="$REPLICA_PRIMARY_PORT" \
        --username=replicator \
        --pgdata="$PGDATA" \
        --wal-method=stream \
        --slot="$REPLICA_SLOT_NAME" \
        --write-recovery-conf \
        --progress \
        --verbose
    chown -R postgres:postgres "$PGDATA"
    log "base backup complete"
}

if [ ! -s "$PGDATA/PG_VERSION" ]; then
    bootstrap_from_primary
else
    log "PGDATA already populated, skipping base backup"
fi

# Hand off to the standard Postgres entrypoint. It'll honour the
# `standby.signal` written by `pg_basebackup --write-recovery-conf` and
# start in standby (read-only, streaming-from-primary) mode.
exec docker-entrypoint.sh "$@"
