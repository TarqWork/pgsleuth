#!/bin/bash
# Load eBPF program from build target directory
# Updated to use name-based filtering instead of PID

echo "Setting up eBPF filesystem..."
mount -t bpf bpf /sys/fs/bpf

echo "Checking eBPF program in target directory..."
ls -la target/bpfel-unknown-none/release/pgsleuth-ebpf

if [ ! -f "target/bpfel-unknown-none/release/pgsleuth-ebpf" ]; then
    echo "ERROR: eBPF program not found at target/bpfel-unknown-none/release/pgsleuth-ebpf"
    echo "Please ensure the rust-dev container has built the eBPF program successfully"
    exit 1
fi

# Configuration: Process name to monitor
TARGET_NAME=${1:-postgres}

echo "Searching for Postgres process..."
# Get Postgres PID
POSTGRES_PID=$(pgrep -x postgres | head -1)

if [ -z "$POSTGRES_PID" ]; then
    # Try psql as fallback to find the backend pid
    POSTGRES_PID=$(psql -U postgres -d postgres -t -c "SELECT pid FROM pg_stat_activity WHERE state = 'active' LIMIT 1;" | tr -d ' ' 2>/dev/null)
fi

FILTER_ARGS=""
if [ -n "$POSTGRES_PID" ]; then
    echo "Found Postgres PID: $POSTGRES_PID"
    
    # Try to get cgroup ID (v2)
    # The path in /proc/PID/cgroup for v2 starts with 0::
    CGROUP_PATH=$(grep '^0::' /proc/$POSTGRES_PID/cgroup | cut -d: -f3)
    if [ -n "$CGROUP_PATH" ]; then
        FULL_CGROUP_PATH="/sys/fs/cgroup$CGROUP_PATH"
        if [ -d "$FULL_CGROUP_PATH" ]; then
            POSTGRES_CGID=$(stat -c %i "$FULL_CGROUP_PATH")
            echo "Found Postgres cgroup ID: $POSTGRES_CGID (Path: $CGROUP_PATH)"
            FILTER_ARGS="--cgroup-id $POSTGRES_CGID"
        fi
    fi
    
    if [ -z "$FILTER_ARGS" ]; then
        echo "Cgroup ID not found, falling back to PID: $POSTGRES_PID"
        FILTER_ARGS="--pid $POSTGRES_PID"
    fi
else
    echo "Postgres process not found, falling back to name-based filtering: $TARGET_NAME"
    FILTER_ARGS="--name $TARGET_NAME"
fi

echo "Starting eBPF loader with filter: $FILTER_ARGS"
EBPF_LOG=/tmp/ebpf-loader.log
RUST_LOG=info ./target/release/pgsleuth-ebpf-loader \
    --bpf-object target/bpfel-unknown-none/release/pgsleuth-ebpf \
    $FILTER_ARGS > $EBPF_LOG 2>&1 &

LOADER_PID=$!
sleep 1

if kill -0 $LOADER_PID 2>/dev/null; then
    echo "eBPF loader started successfully (PID: $LOADER_PID)"
    echo "--- Loader logs ---"
    cat $EBPF_LOG
    echo "--- end loader logs ---"
else
    echo "ERROR: Failed to start eBPF loader"
    cat $EBPF_LOG
    exit 1
fi

echo "eBPF loading complete. Container ready for testing."
echo "Streaming loader logs (Ctrl+C to stop tailing, loader continues)..."
tail -f $EBPF_LOG
