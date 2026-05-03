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

**Start only rust-dev container:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml up rust-dev -d
```

**Start only rust-dev and get shell:**
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml up rust-dev -d && docker compose -f pgsleuth/infra/docker/docker-compose.yml exec rust-dev bash
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
- **Working dir:** /workspace (mounted from project root)

### ebpf-feasibility
- **Purpose:** Run eBPF programs with Postgres
- **Base:** postgres:17-bookworm
- **Capabilities:** BPF, PERFMON (for eBPF operations)
- **Mounts:** /sys/kernel/btf, /sys/fs/bpf (for kernel BTF/BPF access)

## Development Workflow

### Automated Build & Load (Recommended)

The new setup automatically builds and loads the eBPF program:

1. **Start both containers (build + auto-load):**
   ```bash
   docker compose -f pgsleuth/infra/docker/docker-compose.yml up --build
   ```

   - `rust-dev` automatically builds the eBPF program
   - `ebpf-feasibility` automatically loads and runs the eBPF program
   - Artifacts shared via `bpf-builds` volume

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

2. **Access build container to compile eBPF programs:**
   ```bash
   docker compose -f pgsleuth/infra/docker/docker-compose.yml exec rust-dev bash
   # Inside container: cargo build --release
   ```

3. **Access runtime container to run eBPF programs:**
   ```bash
   docker compose -f pgsleuth/infra/docker/docker-compose.yml exec ebpf-feasibility bash
   # Inside container: ./target/bpfel-unknown-none/release/your-program
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
