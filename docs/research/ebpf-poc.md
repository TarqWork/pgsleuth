# eBPF POC — first iteration

**Status:** TODO — plan only. Execution gated step-by-step.

Companion to [`ebpf-feasibility.md`](ebpf-feasibility.md). That doc holds the *verdict*. This doc holds the *plan*.

## Goal

Validate `aya` (Rust eBPF) against Postgres inside Docker. Reproducible from a fresh clone. Each step is a checkpoint reviewed before the next begins.

## Why Docker

- Reproducible kernel surface (no "works on my Linux box").
- Isolates eBPF capability requirements from the dev host.
- macOS dev → Docker Desktop's LinuxKit kernel is itself a feasibility input.

## Container layout

Two containers, both under `infra/docker/`:

### `rust-dev.Dockerfile`
- **Base:** `rust:1.78-bookworm` (matches MSRV).
- **Adds:** `bpf-linker`, `clang`, `libclang-dev`, `libelf-dev`, `zlib1g-dev`, `pkg-config`.
- **Role:** builds the aya program (userspace loader + BPF object).
- **Mounts:** project source at `/workspace`.
- **No privileged ops here** — pure build environment.

### `ebpf-feasibility.Dockerfile`
- **Base (Step 2–4):** minimal Debian + `bpftool`, `libbpf-dev`, kernel headers.
- **Base (Step 5+):** `postgres:17-bookworm` with eBPF tooling layered on top.
- **Role:** load + run the BPF program; attach to target processes.
- **Caps required:** `CAP_BPF` + `CAP_PERFMON` (kernel ≥ 5.8) or fallback `CAP_SYS_ADMIN`.
- **Mounts:** `/sys/kernel/btf`, `/sys/fs/bpf`, build artifacts from rust-dev.

### `docker-compose.yml`
- Wires both as services. Shared volume for built BPF objects.
- `cap_add` and bind mounts only on `ebpf-feasibility`, not `rust-dev`.

## Task list — one step at a time

Each step: do it, verify the listed assertions, then proceed.

### Step 0 — Pre-flight
- [ ] `uname -r` on the host. Record kernel version.
- [ ] Inside a throwaway container, check `ls /sys/kernel/btf/vmlinux`. Present?
- [ ] Confirm Docker Desktop's LinuxKit kernel exposes BTF. **If no → architecture rethink, do not proceed.**

### Step 1 — `rust-dev` container
- [ ] Write `infra/docker/rust-dev.Dockerfile`.
- [ ] `docker build -f infra/docker/rust-dev.Dockerfile -t pgsleuth/rust-dev .`
- [ ] Inside: `cargo --version`, `bpf-linker --version`, `clang --version` all succeed.

### Step 2 — `ebpf-feasibility` container (minimal, no Postgres)
- [ ] Write `infra/docker/ebpf-feasibility.Dockerfile` against a Debian base.
- [ ] Build it.
- [ ] Inside, with `--cap-add=BPF --cap-add=PERFMON`: `bpftool feature probe` runs and reports a usable surface.

### Step 3 — Compose
- [ ] Write `infra/docker/docker-compose.yml` wiring both services.
- [ ] Shared named volume for build output.
- [ ] `docker compose up rust-dev` → builds; `docker compose run ebpf-feasibility` → reads artifact.

### Step 4 — Hello-world aya program
- [ ] New scratch crate (gitignored or under `experiments/`, **not** the workspace).
- [ ] aya kprobe attached to `do_sys_openat2` or `pread64`. Print events to a perf buffer.
- [ ] Build in `rust-dev`, run in `ebpf-feasibility`. See events. Record kernel version + caps used.

### Step 5 — Postgres in the test container
- [ ] Switch `ebpf-feasibility.Dockerfile` to `postgres:17-bookworm` base, re-layer eBPF tooling.
- [ ] Boot Postgres, `psql` from compose service, run a heavy query.
- [ ] Capture backend PID via `pg_stat_activity`.

### Step 6 — Trace `pread64` from a specific Postgres backend
- [ ] Filter the aya program by PID.
- [ ] Aggregate by file descriptor.
- [ ] Resolve fd → relfilenode → table (best effort; record gaps).
- [ ] Decide: is the signal interesting (latency distribution, table-attribution accuracy)?

### Step 7 — Verdict
- [ ] Fill in `ebpf-feasibility.md`: 🟢 / 🟡 / 🔴, kernel version, caps, surprises, what changes in the architecture.
- [ ] Move scratch crate either into `crates/` properly or delete.

## Out of scope for the first POC

- USDT probes inside Postgres.
- Production capability/security model.
- Non-x86_64 architectures.
- CI integration of the POC.

## Open questions to resolve along the way

- Does Docker Desktop's LinuxKit kernel support CO-RE + BTF the way we need? (Step 0.)
- Is one combined container simpler than two? (Revisit after Step 3.)
- Where do BPF objects live — bind-mounted `target/` or named volume? (Revisit after Step 4.)
