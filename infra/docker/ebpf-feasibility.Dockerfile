# eBPF feasibility testing environment with Postgres
# Layer 1: Production-like image — only runtime deps
FROM postgres:17-bookworm AS prod

# Install eBPF runtime dependencies only
RUN apt-get update && apt-get install -y \
    bpftool \
    procps \
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

# Layer 2: Development image — adds build tools and debug utilities
FROM prod AS dev

# Install development / debug dependencies
RUN apt-get update && apt-get install -y \
    libbpf-dev \
    linux-headers-generic \
    vim \
    && rm -rf /var/lib/apt/lists/*
