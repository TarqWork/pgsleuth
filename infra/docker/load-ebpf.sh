#!/bin/bash
# Load eBPF program from build target directory

echo "Setting up eBPF filesystem..."
mount -t bpf bpf /sys/fs/bpf

echo "Checking eBPF program in target directory..."
ls -la target/bpfel-unknown-none/release/pgsleuth-ebpf

if [ ! -f "target/bpfel-unknown-none/release/pgsleuth-ebpf" ]; then
    echo "ERROR: eBPF program not found at target/bpfel-unknown-none/release/pgsleuth-ebpf"
    echo "Please ensure the rust-dev container has built the eBPF program successfully"
    exit 1
fi

echo "Extracting Postgres PID..."
# Get Postgres backend PID from pg_stat_activity
POSTGRES_PID=$(psql -U postgres -d postgres -t -c "SELECT pid FROM pg_stat_activity WHERE state = 'active' LIMIT 1;" | tr -d ' ')

if [ -z "$POSTGRES_PID" ]; then
    echo "WARNING: No active Postgres backend found, using Postgres main process PID"
    POSTGRES_PID=$(pgrep -x postgres | head -1)
fi

if [ -z "$POSTGRES_PID" ]; then
    echo "ERROR: Could not find Postgres PID"
    exit 1
fi

echo "Found Postgres PID: $POSTGRES_PID"

echo "Starting eBPF loader with Postgres PID: $POSTGRES_PID"
# Use eBPF loader instead of bpftool to avoid legacy map definition issues
./target/release/pgsleuth-ebpf-loader --bpf-object target/bpfel-unknown-none/release/pgsleuth-ebpf --pid $POSTGRES_PID &

if [ $? -eq 0 ]; then
    echo "eBPF loader started successfully"
    echo "Monitoring Postgres PID: $POSTGRES_PID"
else
    echo "ERROR: Failed to start eBPF loader"
    exit 1
fi

echo "eBPF loading complete. Container ready for testing."
