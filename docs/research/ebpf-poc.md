# eBPF POC — first iteration

**Status (2026-05-22):** Steps 0–5 done. Step 6 partially done (PID/cgroup/name filtering on `vfs_open`, not `pread64` yet). Scaffolding for the v0 skeleton — including the Postgres extension and Docker integration — landed this session; full data-path validation still pending. See [Current status](#current-status-2026-05-22) below.

Companion to [`ebpf-feasibility.md`](ebpf-feasibility.md). That doc holds the *verdict*. This doc holds the *plan*.

## Current status (2026-05-22)

This section supersedes the step-by-step checklist for live status. The original task list below is preserved as the historical plan.

### What's working end-to-end

- **eBPF program** loads in `ebpf-feasibility` container, attaches to `vfs_open`, filters by cgroup ID / PID / `comm`, emits matched events through a `RingBuf` to userspace.
- **Userspace loader** (`pgsleuth-ebpf-loader`) consumes the ring buffer, supports `--cgroup-id` / `--pid` / `--name` flags. `load-ebpf.sh` resolves Postgres' cgroup ID from `/proc/<pid>/cgroup` (v2) and passes it as the primary filter.
- **Postgres extension** (`pgsleuth-pg-ext`, pgrx 0.12.9) defines two SQL functions — `pgsleuth_wal_device()` and `pgsleuth_postmaster_pid()` — packaged via `cargo pgrx package` and installed into the runtime container by `install-pg-ext.sh` at boot.
- **Docker integration** — `rust-dev` carries the pgrx toolchain (cargo-pgrx pinned to 0.12.9, `postgresql-server-dev-17` from apt.postgresql.org, `cargo pgrx init` against system pg_config so no managed PG is downloaded). `build.sh all` builds eBPF + loader + common + pg-ext in one shot.

### What's NOT validated yet

- **Loader ↔ PG extension wiring** — the loader does not yet call the extension at startup. Both pieces exist; they don't talk.
- **SQL function correctness** — `pgsleuth_wal_device()` output not yet checked against an independent source (e.g., `stat -c '%d' $PGDATA/pg_wal`).
- **Kernel-side device filtering** — the eBPF program filters by PID/cgroup/name, not by `dev_t`. Once the loader retrieves `pgsleuth_wal_device()`, the kernel program needs a `dev_t` filter to scope block I/O to the WAL device.
- **OTel emission** — loader logs events; does not yet emit OTel histograms.

### Immediate next steps

**Next-1: Loader retrieves something from the PG extension.**

Smallest possible end-to-end proof that the integration is real:
- Add `tokio-postgres` to `pgsleuth-ebpf-loader`.
- New `--pg-conn` arg (default `postgres://postgres@localhost/postgres`).
- At startup, the loader connects and runs `SELECT pgsleuth_wal_device(), pgsleuth_postmaster_pid();`.
- Log the results. Use the postmaster PID as the default for PID/cgroup filtering when `--pid` / `--cgroup-id` are not explicitly passed (keeping current flags as overrides).
- Validates: pg-ext SQL surface, loader's ability to talk to PG, and the full stack from kernel → ring buffer → loader → SQL → log.

**Next-2: Promote the scratch POC into the main application directory structure.**

`pgsleuth-ebpf-poc/` is currently a sibling repo named "POC" — fine for feasibility, wrong for the product. Move the surviving crates into the main `pgsleuth/` tree under a coherent layout (something like `pgsleuth/crates/{ebpf,ebpf-common,loader,pg-ext}/` plus `pgsleuth/brain/` for the deferred Python brain). The exact layout is its own design decision and should be planned, not bolted on. Reference `pgsleuth/CLAUDE.md` (architecture invariants) and `pgsleuth/docs/design/000-architecture.md` before deciding.

After the move, retire `pgsleuth-ebpf-poc` from active development (keep the git history but archive the repo).

### Session summary — 2026-05-21 → 2026-05-22

Major deliverables of this session:

| Deliverable | Outcome |
|---|---|
| 19-alarm observability catalog with tiered eBPF-vs-DB detection model | `pgsleuth/docs/research/Database Observability Alarms.md` (committed) |
| GitHub project board populated with all alarms as backlog items + scaffold item marked Done | https://github.com/orgs/TarqWork/projects/2 |
| `pgsleuth-pg-ext` pgrx extension crate scaffolded with `pgsleuth_wal_device()` + `pgsleuth_postmaster_pid()` | `pgsleuth-ebpf-poc/pgsleuth-pg-ext/` |
| Docker `rust-dev` upgraded with pgrx toolchain (cargo-pgrx 0.12.9, PG 17 headers, `cargo pgrx init`) | `pgsleuth/infra/docker/rust-dev.Dockerfile` |
| `build.sh` extended with `pg-ext` / `pg-ext-test` targets, `--backtrace` / `--full` flags, `--out-dir $CARGO_TARGET_DIR/pg-ext-pkg` | `pgsleuth/infra/docker/build.sh` |
| Idempotent install helper, sourced by both `setup-postgres.sh` (boot-time) and `load-ebpf.sh` (manual rerun) | `pgsleuth/infra/docker/install-pg-ext.sh` |

### Where to look — design decisions, code, and rationale

| Topic | Where it lives |
|---|---|
| 19 multi-signal alarms, per-alarm eBPF program type + attach point + DBA/SysAdmin/Linux-dev/Architect perspectives | `pgsleuth/docs/research/Database Observability Alarms.md` |
| Tier-1→Tier-4 prioritization with detection-model column | same doc § "Implementation Priority" |
| Why Alarm #3 (Fsync Jitter) was chosen as the v0 skeleton — pipeline-development grounds, not alarm-detection grounds | same doc § "Skeleton POC" |
| Pure-DB alarms (#7 TXID, #8 THP, #17 Logical Decoding, #19 Idle-in-Tx) and why eBPF was dropped from each | same doc, per-alarm "Detection model" blocks |
| `postgresql-server-dev-17` is headers-only (~30–50 MB), NOT the PG server | `pgsleuth-ebpf-poc/pgsleuth-pg-ext/README.md` § "Note on postgresql-server-dev-17" |
| pgrx and cargo-pgrx are version-locked at 0.12.9 — bump both together | `pgsleuth-ebpf-poc/pgsleuth-pg-ext/Cargo.toml` (pin comment) + `pgsleuth/infra/docker/rust-dev.Dockerfile` |
| Why `cargo pgrx init --pg17 $(which pg_config)` is in the Dockerfile (PGRX_HOME requirement; does NOT download managed PG) | `pgsleuth/infra/docker/rust-dev.Dockerfile` cargo-pgrx init layer comment |
| Why `pgrx_embed_<crate-name>` companion bin target is mandatory for SQL-entity generation | `pgsleuth-ebpf-poc/pgsleuth-pg-ext/src/bin/pgrx_embed.rs` + matching `[[bin]]` in `Cargo.toml` |
| Why `--out-dir` is anchored to `$CARGO_TARGET_DIR` (relative paths resolve from CWD, which is outside the shared mount in rust-dev) | `pgsleuth/infra/docker/build.sh` `build_pg_ext` function comment block |
| The `PG_EXT_OUT_DIR` ↔ `PG_EXT_PKG` contract between build and install scripts | `pgsleuth/infra/docker/install-pg-ext.sh` `PG_EXT_PKG` comment block |
| Idempotent install design (cp overwrites, `CREATE EXTENSION IF NOT EXISTS`, read-only smoke test) | `pgsleuth/infra/docker/install-pg-ext.sh` header |
| Why install runs in BOTH `setup-postgres.sh` (boot) AND `load-ebpf.sh` (manual rerun) — covers both ordering cases | `pgsleuth/infra/docker/setup-postgres.sh` install hook comment |
| Docker Desktop bind-mount staleness on atomic-write edits — `compose run` / `touch` / restart as fixes | This session's git log + the `[Skeleton] PG extension scaffold + Docker integration` project item |
| `RUST_BACKTRACE` flag handling in build.sh | `pgsleuth/infra/docker/build.sh` top-of-file flag-parsing block |

### Source commits — this session

- `pgsleuth@8e87315` — docs(research): add observability alarms catalog and eBPF reference notes
- `pgsleuth@d502c26` — feat(ebpf): cgroup/PID/name filter fallback chain in load-ebpf.sh
- `pgsleuth@a786d9d` — chore(docs): untrack local kernel-function research dump
- `pgsleuth@e7188af` — feat(docker): wire pgsleuth pg-ext build + install into the docker flow
- `pgsleuth-ebpf-poc@42d0c5a` — feat(ebpf): filter by cgroup/PID/name and emit events via ring buffer
- `pgsleuth-ebpf-poc@1669d6c` — feat(pg-ext): scaffold pgsleuth-pg-ext pgrx extension

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
- [x] Switch `ebpf-feasibility.Dockerfile` to `postgres:17-bookworm` base, re-layer eBPF tooling.
- [x] Boot Postgres, `psql` from compose service, run a heavy query.
- [x] Capture backend PID via `pg_stat_activity`. (Plus cgroup ID via `/proc/<pid>/cgroup`.)

### Step 6 — Trace `pread64` from a specific Postgres backend
*Partially superseded — we now attach to `vfs_open` and filter by PID / cgroup-ID / `comm`. `pread64` per-backend is still on the table but no longer the next milestone; see [Immediate next steps](#immediate-next-steps).*
- [x] Filter the aya program by PID. (Plus cgroup ID and process name.)
- [ ] Aggregate by file descriptor.
- [ ] Resolve fd → relfilenode → table — re-scoped: deferred until Alarm #1 (Plan Regression) becomes active; the v0 skeleton (Alarm #3, Fsync Jitter) needs `dev_t`-based filtering instead.
- [x] Decide: is the signal interesting? **Yes** — proceeded to design the 19-alarm catalog and v0 skeleton (see `Database Observability Alarms.md`).

### Step 7 — Verdict
- [ ] Fill in `ebpf-feasibility.md`: 🟢 / 🟡 / 🔴, kernel version, caps, surprises, what changes in the architecture.
- [ ] Move scratch crate either into `crates/` properly or delete. (See **Next-2** in [Immediate next steps](#immediate-next-steps).)

## Out of scope for the first POC

- USDT probes inside Postgres.
- Production capability/security model.
- Non-x86_64 architectures.
- CI integration of the POC.

## Open questions to resolve along the way

- Does Docker Desktop's LinuxKit kernel support CO-RE + BTF the way we need? (Step 0.)
- Is one combined container simpler than two? (Revisit after Step 3.)
- Where do BPF objects live — bind-mounted `target/` or named volume? (Revisit after Step 4.)
