# PGSleuth eBPF Docker Infrastructure

Docker setup for eBPF feasibility POC with Rust build environment and Postgres runtime.

## Quick Start

**Build and run everything (one command):**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml up --build -d
```

This builds both images if needed and starts the containers in detached mode.

**Build, run, and get shell prompt immediately:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml up --build -d && docker compose -f pgsleuth/infra/docker/docker-compose.yml exec rust-dev bash
```

This builds everything, starts containers in detached mode, and drops you into the build container shell.

**Build, run, and get eBPF runtime shell:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml up --build -d && docker compose -f pgsleuth/infra/docker/docker-compose.yml exec ebpf-feasibility bash
```

This builds everything, starts containers in detached mode, and drops you into the eBPF runtime container shell.

**Build with the dev image variant (adds build tools + debug utilities):**
```bash
EBPF_TARGET=dev docker compose -f pgsleuth/infra/docker/docker-compose.yml up --build -d
```

See [Image Variants](#image-variants) for what `prod` vs `dev` includes.

**Start only rust-dev container:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml up rust-dev -d
```

**Start only rust-dev and get shell:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml up rust-dev -d && docker compose -f pgsleuth/infra/docker/docker-compose.yml exec rust-dev bash
```

## Image Variants

The `ebpf-feasibility` image is a multi-stage build with two targets, selected
via the `EBPF_TARGET` environment variable (default: `prod`).

| Variant | Selected by | Contents |
| --- | --- | --- |
| `prod` (default) | `EBPF_TARGET=prod` or unset | Runtime only: `bpftool`, `procps` on top of `postgres:17-bookworm`. Closer to a production-like image. |
| `dev` | `EBPF_TARGET=dev` | Everything in `prod`, plus build/debug tooling: `libbpf-dev`, `linux-headers-generic`, `vim`. Use when iterating on eBPF programs inside the runtime container. |

The variable controls both the Dockerfile build target and the resulting image
tag (`pgsleuth/ebpf-feasibility:prod` vs `:dev`), so the two images coexist on
disk without overwriting each other.

**Examples:**
```bash
# Default (prod) — same as omitting the variable
docker compose -f pgsleuth/infra/docker/docker-compose.yml up --build -d

# Dev variant
EBPF_TARGET=dev docker compose -f pgsleuth/infra/docker/docker-compose.yml up --build -d

# Build only (no run)
EBPF_TARGET=dev docker compose -f pgsleuth/infra/docker/docker-compose.yml build ebpf-feasibility
```

To make the variant sticky for a shell session:
```bash
export EBPF_TARGET=dev
```

## Common Commands

### From project root:

**Build images (if needed):**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml build
```

**Start containers:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml up -d
```

**Stop containers:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml down
```

**View logs:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml logs -f
```

### From docker directory:

If you're in `pgsleuth/infra/docker/`, you can omit the compose file path:
```bash
cd pgsleuth/infra/docker
docker compose up --build -d
```

## Access Container Shell

**Access build container (rust-dev):**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml exec rust-dev bash
```

**Access runtime container (ebpf-feasibility):**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml exec ebpf-feasibility bash
```

## Container Details

### rust-dev
- **Purpose:** Build eBPF programs with Rust
- **Base:** rustlang/rust:nightly
- **Tools:** cargo, clang, bpf-linker, libclang-dev
- **Working dir:** /workspace/source/pgsleuth/ (source code; eBPF crates live at `crates/pgsleuth-ebpf*`, `crates/pgsleuth-pg-ext`, `crates/xtask` after #19)
- **Build output:** /workspace/build/target/ (shared with ebpf-feasibility via `./ebpf-target` host mount)

### ebpf-feasibility
- **Purpose:** Run eBPF programs with Postgres
- **Base:** postgres:17-bookworm
- **Build:** Multi-stage Dockerfile with two targets — `prod` (runtime-only) and `dev` (adds `libbpf-dev`, `linux-headers-generic`, `vim`). Selected via the `EBPF_TARGET` env var; see [Image Variants](#image-variants).
- **Capabilities:** BPF, PERFMON (for eBPF operations)
- **Mounts:** /sys/kernel/btf, /sys/fs/bpf (for kernel BTF/BPF access)

## Development Workflow

### Automated Build & Load (Recommended)

The new setup automatically builds and loads the eBPF program:

1. **Start both containers (build + auto-load):**
   ```bash
   docker compose -f pgsleuth/infra/docker/docker-compose.yml up --build
   ```

   - `rust-dev` automatically runs the build script (`bash /workspace/build.sh ebpf`)
   - `ebpf-feasibility` automatically loads and runs the eBPF program
   - Artifacts shared via `./ebpf-target` host directory mount

2. **Monitor the process:**
   ```bash
   docker compose -f pgsleuth/infra/docker/docker-compose.yml logs -f
   ```

3. **Stop when done:**
   ```bash
   docker compose -f pgsleuth/infra/docker/docker-compose.yml down
   ```

### Manual Workflow (For Development)

1. **Start environment:**
   ```bash
   docker compose -f pgsleuth/infra/docker/docker-compose.yml up --build -d
   ```

2. **Access build container to run build commands:**
   ```bash
   docker compose -f pgsleuth/infra/docker/docker-compose.yml exec rust-dev bash
   # Inside container, run build script commands:
   bash /workspace/build.sh ebpf    # build eBPF only
   bash /workspace/build.sh all     # build everything
   bash /workspace/build.sh clean   # clean artifacts
   ```

3. **Access runtime container to inspect/load eBPF programs:**
   ```bash
   docker compose -f pgsleuth/infra/docker/docker-compose.yml exec ebpf-feasibility bash
   # Inside container, inspect built artifacts:
   ls -la target/bpfel-unknown-none/release/pgsleuth-ebpf
   ```

4. **Stop when done:**
   ```bash
   docker compose -f pgsleuth/infra/docker/docker-compose.yml down
   ```

### Individual Service Control

**Build eBPF program only:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml run rust-dev
```

**Load and run eBPF program only:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml run ebpf-feasibility
```

## Troubleshooting

**Check container status:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml ps
```

**Rebuild images from scratch:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml build --no-cache
```

**View container logs:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml logs rust-dev
docker compose -f pgsleuth/infra/docker/docker-compose.yml logs ebpf-feasibility
```
