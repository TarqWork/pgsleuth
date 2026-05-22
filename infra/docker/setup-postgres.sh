#!/bin/bash
# Setup and start Postgres for eBPF feasibility testing.
# Also installs the pgsleuth extension at boot if its build artifacts
# are already present in the shared target/ tree. Idempotent — safe to
# re-run; safe when artifacts are missing (skips with a warning).

echo "Starting Postgres..."
docker-entrypoint.sh postgres &

# Wait for Postgres to be ready
echo "Waiting for Postgres to be ready..."
while ! pg_isready -q; do
    sleep 1
done

echo "Postgres is ready and accepting connections"
echo "You can now connect with: psql -U postgres -h localhost"

# Install the pgsleuth extension if its packaged artifacts exist in
# /workspace/build/target/pgsleuth-pg-ext/pkg/. This covers the common
# case where rust-dev finished `build.sh pg-ext` before ebpf-feasibility
# boots. For the case where the user builds pg-ext *after* this script
# has already run, load-ebpf.sh also calls install_pg_extension when
# invoked manually — so a later build is still picked up without
# restarting the container.
cd /workspace/build
# shellcheck disable=SC1091
source /workspace/install-pg-ext.sh
install_pg_extension

# Keep the container running
sleep infinity
