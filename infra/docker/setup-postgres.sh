#!/bin/bash
# Setup and start Postgres for eBPF feasibility testing

echo "Starting Postgres..."
docker-entrypoint.sh postgres &

# Wait for Postgres to be ready
echo "Waiting for Postgres to be ready..."
while ! pg_isready -q; do
    sleep 1
done

echo "Postgres is ready and accepting connections"
echo "You can now connect with: psql -U postgres -h localhost"

# Keep the container running
sleep infinity
