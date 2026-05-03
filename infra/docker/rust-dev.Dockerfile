# Rust eBPF build environment
# Base: rust nightly (for latest eBPF tooling support)
FROM rustlang/rust:nightly

# Install eBPF build dependencies
RUN apt-get update && apt-get install -y \
    clang \
    libclang-dev \
    libelf-dev \
    zlib1g-dev \
    pkg-config \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# Install bpf-linker via cargo (Rust package manager) - latest version with nightly
RUN cargo install bpf-linker

# Install rust-src for building BPF targets
RUN rustup component add rust-src

# Set working directory
WORKDIR /workspace

# Mount point for project source
# Usage: docker run -v $(pwd):/workspace pgsleuth/rust-dev
