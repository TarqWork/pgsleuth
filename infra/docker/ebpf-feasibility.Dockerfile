# eBPF feasibility testing environment with Postgres
# Base: postgres:17-bookworm with eBPF tooling layered on top
FROM postgres:17-bookworm

# Install eBPF runtime dependencies
RUN apt-get update && apt-get install -y \
    bpftool \
    libbpf-dev \
    linux-headers-generic \
    procps \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Create directories for eBPF operations
RUN mkdir -p /sys/fs/bpf /sys/kernel/btf

# Set working directory
WORKDIR /workspace

# Environment variables for eBPF operations
ENV BPF_OBJECT_PATH=/workspace/target/bpfel-unknown-none/release/

# Default command to keep container running for eBPF operations
CMD ["tail", "-f", "/dev/null"]

# Usage: docker run --cap-add=BPF --cap-add=PERFMON -v /sys/kernel/btf:/sys/kernel/btf:ro -v /sys/fs/bpf:/sys/fs/bpf pgsleuth/ebpf-feasibility
