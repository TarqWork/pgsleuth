# Rust eBPF build environment
# Base: rust nightly (for latest eBPF tooling support)
FROM rustlang/rust:nightly

# Install eBPF build dependencies + tools needed to add the official
# Postgres APT repository (curl, gnupg, lsb-release, ca-certificates).
RUN apt-get update && apt-get install -y \
    clang \
    libclang-dev \
    libelf-dev \
    zlib1g-dev \
    pkg-config \
    linux-headers-generic \
    curl \
    gnupg \
    lsb-release \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install bpf-linker via cargo (Rust package manager) - latest version with nightly
RUN cargo install bpf-linker

# Install rust-src for building BPF targets
RUN rustup component add rust-src

# --- Postgres extension build dependencies -----------------------------------
# pgsleuth-pg-ext uses pgrx, which requires:
#   - postgresql-server-dev-17 (provides pg_config + server headers)
#   - cargo-pgrx pinned to the same version as the pgrx crate dependency
# Bookworm's default repos only carry server-dev-15, so we add the official
# PG APT repo first.
RUN curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        | gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg \
    && echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y postgresql-server-dev-17 \
    && rm -rf /var/lib/apt/lists/*

# cargo-pgrx must match the `pgrx` dependency version pinned in
# pgsleuth-ebpf-poc/pgsleuth-pg-ext/Cargo.toml. Bump both together.
RUN cargo install --locked cargo-pgrx --version 0.12.9

# Initialise $PGRX_HOME (~/.pgrx/) so pgrx can find its config file.
# Even `cargo pgrx package` (which only builds against the system PG)
# requires this directory to exist. Pointing `--pg17` at the system
# pg_config means pgrx does NOT download or compile a managed Postgres —
# it just writes a config that resolves PG_CONFIG_PATH to the system one.
RUN cargo pgrx init --pg17 "$(which pg_config)"

# Set working directory
WORKDIR /workspace

# Mount point for project source
# Usage: docker run -v $(pwd):/workspace pgsleuth/rust-dev
