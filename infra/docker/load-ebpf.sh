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

echo "Loading eBPF program..."
bpftool prog load target/bpfel-unknown-none/release/pgsleuth-ebpf /sys/fs/bpf/pgsleuth-ebpf

if [ $? -eq 0 ]; then
    echo "eBPF program loaded successfully"
    echo "Program list:"
    bpftool prog list | grep pgsleuth
else
    echo "ERROR: Failed to load eBPF program"
    exit 1
fi

echo "eBPF loading complete. Container ready for testing."
