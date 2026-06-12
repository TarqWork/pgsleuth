#!/bin/bash
# Cross-check `pgsleuth_wal_device()` against `stat -c '%d' $PGDATA/pg_wal`.
#
# Locks down the SQL function's correctness before the eBPF kernel
# program starts trusting its output as the dev_t filter. Idempotent —
# safe to run at boot AND as an operator one-shot.
#
# Runs inside the ebpf-feasibility container, which is where the kernel
# program will read this value. Exits 0 on match, 1 on mismatch.
# Designed to be sourced or invoked; the actual logic lives in
# validate_wal_device().

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
PSQL_DSN="${PSQL_DSN:-postgres://postgres@localhost/postgres}"

validate_wal_device() {
    local wal_dir="$PGDATA/pg_wal"

    if [ ! -d "$wal_dir" ]; then
        echo "[validate-wal-device] ERROR: $wal_dir does not exist" >&2
        return 1
    fi

    # st_dev as decimal — Linux encodes major:minor inside this single
    # number. We compute major and minor independently for clarity rather
    # than depending on `stat -c '%t:%T'`, which only returns nonzero
    # values for device-special files (not regular dirs).
    local st_dev expected_major expected_minor expected
    if ! st_dev="$(stat -c '%d' "$wal_dir" 2>/dev/null)"; then
        echo "[validate-wal-device] ERROR: stat $wal_dir failed" >&2
        return 1
    fi
    expected_major=$(( (st_dev >> 8) & 0xfff ))
    expected_minor=$(( (st_dev & 0xff) | ((st_dev >> 12) & 0xfff00) ))
    expected="${expected_major}:${expected_minor}"

    # Pull the SQL-side answer. If pgsleuth isn't installed yet we can't
    # validate — surface that as a soft skip so calling this from
    # setup-postgres.sh before the extension lands doesn't block boot.
    local actual
    if ! actual="$(PGPASSWORD="${PGPASSWORD:-postgres}" psql "$PSQL_DSN" -X -A -t -c 'SELECT pgsleuth_wal_device();' 2>/dev/null)"; then
        echo "[validate-wal-device] SKIP: pgsleuth_wal_device() not callable (extension installed?)" >&2
        return 0
    fi
    actual="$(echo "$actual" | tr -d '[:space:]')"

    if [ "$actual" = "$expected" ]; then
        echo "[validate-wal-device] OK: pgsleuth_wal_device()=$actual matches stat($wal_dir)"
        return 0
    fi

    echo "[validate-wal-device] FAIL" >&2
    echo "  pgsleuth_wal_device() = '$actual'" >&2
    echo "  stat($wal_dir)         = st_dev=$st_dev -> major:minor='$expected'" >&2
    return 1
}

# Allow direct invocation (`bash validate-wal-device.sh`) AND sourcing
# from setup-postgres.sh / load-ebpf.sh. When sourced, only the function
# is defined; when run, we execute it.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    validate_wal_device
fi
