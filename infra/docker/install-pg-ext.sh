#!/bin/bash
# Shared helper for installing the pgsleuth Postgres extension.
#
# Defines `install_pg_extension` as a function. Source this file from
# scripts that need the install step (setup-postgres.sh at container
# boot, load-ebpf.sh when invoked manually). Calling the function
# multiple times is safe — every step is idempotent:
#
#   - `cp` overwrites existing files in pkglibdir / sharedir
#   - `CREATE EXTENSION IF NOT EXISTS` is a no-op when already installed
#   - the smoke-test SELECT has no side effects
#
# Caveat: if the .so is *replaced* under a running backend, existing
# sessions keep the old image until reconnect. Restart the container
# (or reconnect) after rebuilding the extension's C surface.

# Root directory under which to search for the pgrx-staged install tree.
# build.sh's `pg-ext` target writes here via
# `--out-dir $CARGO_TARGET_DIR/pg-ext-pkg`, so the resolved absolute
# path is `/workspace/build/target/pg-ext-pkg/`. ebpf-feasibility's
# working_dir is `/workspace/build`, so the relative path
# `target/pg-ext-pkg` resolves to the same absolute path — they meet
# inside the shared mount.
#
# Layout under PG_EXT_PKG:
#   usr/lib/postgresql/<NN>/lib/pgsleuth.so
#   usr/share/postgresql/<NN>/extension/pgsleuth.control
#   usr/share/postgresql/<NN>/extension/pgsleuth--<ver>.sql
#
# Contract: bump PG_EXT_OUT_DIR (build.sh) and PG_EXT_PKG (here)
# together if you ever rename the staging directory. Callers may
# override PG_EXT_PKG before sourcing if they keep artifacts elsewhere.
: "${PG_EXT_PKG:=target/pg-ext-pkg}"

install_pg_extension() {
    echo "=== Installing pgsleuth Postgres extension (idempotent) ==="

    if [ ! -d "$PG_EXT_PKG" ]; then
        echo "WARNING: pgsleuth-pg-ext package not found at $PG_EXT_PKG"
        echo "         Build it with: bash /workspace/build.sh pg-ext  (in rust-dev)"
        echo "         Skipping extension install — caller can continue."
        return 0
    fi

    local pkglibdir sharedir so_src ctrl_src sql_src
    pkglibdir=$(pg_config --pkglibdir 2>/dev/null)
    sharedir=$(pg_config --sharedir 2>/dev/null)
    if [ -z "$pkglibdir" ] || [ -z "$sharedir" ]; then
        echo "WARNING: pg_config not available; cannot locate extension install dirs."
        echo "         Skipping extension install."
        return 0
    fi

    so_src=$(find "$PG_EXT_PKG" -name 'pgsleuth.so' | head -1)
    ctrl_src=$(find "$PG_EXT_PKG" -name 'pgsleuth.control' | head -1)
    sql_src=$(find "$PG_EXT_PKG" -name 'pgsleuth--*.sql' | head -1)

    if [ -z "$so_src" ] || [ -z "$ctrl_src" ] || [ -z "$sql_src" ]; then
        echo "WARNING: pgsleuth-pg-ext artifacts incomplete under $PG_EXT_PKG"
        echo "         Found: so='$so_src' control='$ctrl_src' sql='$sql_src'"
        echo "         Skipping extension install."
        return 0
    fi

    echo "Copying extension artifacts:"
    echo "  $so_src   -> $pkglibdir/"
    cp "$so_src" "$pkglibdir/"
    echo "  $ctrl_src -> $sharedir/extension/"
    cp "$ctrl_src" "$sharedir/extension/"
    echo "  $sql_src  -> $sharedir/extension/"
    cp "$sql_src" "$sharedir/extension/"

    echo "Registering extension in Postgres..."
    if ! psql -U postgres -d postgres -c "CREATE EXTENSION IF NOT EXISTS pgsleuth;" 2>&1; then
        echo "WARNING: CREATE EXTENSION failed; continuing without it."
        return 0
    fi

    echo "Extension smoke test:"
    psql -U postgres -d postgres -c \
        "SELECT pgsleuth_wal_device() AS wal_device, pgsleuth_postmaster_pid() AS postmaster_pid;" \
        || echo "WARNING: extension smoke test failed."

    echo "=== Extension install complete ==="
}
