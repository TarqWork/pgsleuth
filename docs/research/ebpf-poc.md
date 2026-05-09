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
- [x] `uname -r` on the host. Record kernel version.
- [x] Inside a throwaway container, check `ls /sys/kernel/btf/vmlinux`. Present?
- [x] Confirm Docker Desktop's LinuxKit kernel exposes BTF. **If no → architecture rethink, do not proceed.**

### Step 1 — `rust-dev` container
- [x] Write `infra/docker/rust-dev.Dockerfile`.
- [x] `docker build -f infra/docker/rust-dev.Dockerfile -t pgsleuth/rust-dev .`
- [x] Inside: `cargo --version`, `bpf-linker --version`, `clang --version` all succeed.

### Step 2 — `ebpf-feasibility` container (minimal, no Postgres)
- [x] Write `infra/docker/ebpf-feasibility.Dockerfile` against a Debian base.
- [x] Build it.
- [x] Inside, with `--cap-add=BPF --cap-add=PERFMON`: `bpftool feature probe` runs and reports a usable surface.

### Step 3 — Compose
- [x] Write `infra/docker/docker-compose.yml` wiring both services.
- [x] Shared named volume for build output.
- [x] `docker compose up rust-dev` → builds; `docker compose run ebpf-feasibility` → reads artifact.

### Step 4 — Hello-world aya program
- [x] New scratch crate in `pgsleuth-ebpf-poc/` directory.
- [x] aya kprobe attached to `do_sys_openat2`. Minimal working implementation.
- [x] Build in `rust-dev`, run in `ebpf-feasibility`. Successfully loaded and verified.

#### Step 4 Implementation Summary

**✅ COMPLETED** - Successfully implemented and tested a working eBPF kprobe program.

**Key Accomplishments:**
- **Program Structure**: Created complete aya-based eBPF project in `pgsleuth-ebpf-poc/` with proper workspace setup
- **Kprobe Implementation**: Implemented kprobe attached to `do_sys_openat2` syscall
- **Build System**: Working xtask-based build system using `cargo run --bin xtask -- build-ebpf`
- **Container Infrastructure**: Both `rust-dev` (build) and `ebpf-feasibility` (run) containers functional
- **Modern libbpf Compatibility**: Resolved legacy map definition issues for contemporary libbpf v1.0+

**Technical Details:**
- **eBPF Program**: Minimal kprobe that attaches to `do_sys_openat2` and returns success
- **Build Target**: `bpfel-unknown-none` using `cargo build -Zbuild-std`
- **Loading Method**: `bpftool prog load` with BPF filesystem mounting
- **Verification**: Program loads as ID 111 with name "pgsleuth_ebpf" and successfully attaches

**Container Setup:**
- **rust-dev**: Rust nightly + eBPF toolchain (clang, bpf-linker, rust-src)
- **ebpf-feasibility**: `postgres:17-bookworm` base + bpftool + libbpf-dev + BPF capabilities

**Capabilities required (observed):**
- Easiest: **`CAP_SYS_ADMIN` alone** — implies the others, shortest `docker run` line, fine for local feasibility.
- Principled (kernel ≥ 5.8): `CAP_BPF + CAP_PERFMON`, **plus** `CAP_SYS_ADMIN` for bpffs mount and some map ops, and likely `CAP_NET_ADMIN` once we touch network-side tracing.
- Compose currently grants all four (`BPF, PERFMON, NET_ADMIN, SYS_ADMIN`). Tightening is a Phase 5 concern.

**Files Modified/Created:**
- `pgsleuth-ebpf-poc/pgsleuth-ebpf/src/main.rs` - eBPF kprobe implementation
- `pgsleuth-ebpf-poc/xtask/src/main.rs` - build system
- `pgsleuth-ebpf-poc/pgsleuth-ebpf-common/src/lib.rs` - shared types (prepared for future use)
- `pgsleuth/infra/docker/rust-dev.Dockerfile` - build environment
- `pgsleuth/infra/docker/ebpf-feasibility.Dockerfile` - runtime environment
- `pgsleuth/infra/docker/build.sh` - in-container build entry point
- `pgsleuth/infra/docker/docker-compose.yml` - wires both services + shared `./ebpf-target` volume

**Verification (current build flow):**

> **`up` vs `run` — pick one and stick with it.** `docker compose up` honors
> the `container_name:` pinned in compose (`pgsleuth-ebpf-feasibility`), so
> follow-up `docker exec` / `docker compose exec` commands work by name.
> `docker compose run` creates a one-off container with an auto-generated
> name like `docker-ebpf-feasibility-run-<hash>` and ignores `container_name`,
> so `docker exec pgsleuth-ebpf-feasibility …` will fail with "No such
> container". For verification, prefer `up -d`.

From `pgsleuth/infra/docker/`:
```bash
# build + start in background (uses the pinned container_name)
docker compose up --build -d

# Inspect the loaded program
docker exec pgsleuth-ebpf-feasibility bpftool prog list | grep pgsleuth
# or, equivalent via compose:
docker compose exec ebpf-feasibility bpftool prog list | grep pgsleuth

# Tear down
docker compose down
```

From project root (equivalent, no `cd` needed):
```bash
docker compose -f pgsleuth/infra/docker/docker-compose.yml up --build -d
docker exec pgsleuth-ebpf-feasibility bpftool prog list | grep pgsleuth
docker compose -f pgsleuth/infra/docker/docker-compose.yml down
```

If a container is already running but was started with `compose run`
(ephemeral name), grab it by image instead:
```bash
docker exec $(docker ps -q --filter ancestor=pgsleuth/ebpf-feasibility) bpftool prog list | grep pgsleuth
```

**Result**: `111: kprobe  name pgsleuth_ebpf  tag a04f5eef06a7f555`

**Next Steps Ready**: Infrastructure proven working, ready for Step 5 Postgres integration.

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
