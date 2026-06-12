# 002 — Promoting POC crates into the main pgsleuth tree

| | |
|---|---|
| Status | Draft |
| Author | @gagan |
| Created | 2026-06-12 |
| Last revised | 2026-06-12 |
| Supersedes | none |
| Related | [`000-architecture.md`](000-architecture.md), [`001-rule-schema.md`](001-rule-schema.md) |

## Problem

The eBPF feasibility POC lived in a sibling repo, `pgsleuth-ebpf-poc/`. Its
verdict ([`docs/research/ebpf-feasibility.md`](../research/ebpf-feasibility.md))
was *go* — the kernel-side BPF program, the userspace loader, the shared
no-std types, and the pgrx Postgres extension all work end-to-end inside the
existing Docker flow at `infra/docker/`. The POC repo also accumulated
build orchestration (`xtask`) and a small but real set of build-environment
choices (nightly Rust, `bpfel-unknown-none` target, `cargo-pgrx` 0.12.9,
PG 17 server headers) that are now load-bearing for v0.1 delivery.

Keeping these crates in a separate repo creates three problems:

1. **Single-workspace invariant broken.** `pgsleuth/CLAUDE.md` says the two
   stacks must be testable from one command (`make ci`). The POC crates fall
   outside that gate today.
2. **Path coupling already exists.** `pgsleuth/infra/docker/` compose paths
   reach into `../../pgsleuth-ebpf-poc/`. Every Tier-1 alarm task touches
   the eBPF crates; they need to be discoverable from one `cargo metadata`.
3. **License + repo metadata drift.** POC is dual-licensed
   (`MIT OR Apache-2.0`) and points at the POC GitHub repo. The main
   project is `Apache-2.0` only. Every new crate landing for the alarms
   would have to choose.

This doc resolves the layout. The archival of the POC repo itself is the
separate task **#20**, gated on this one.

## Goals

- Promoted crates land in `pgsleuth/crates/` under the same naming
  convention as the existing userspace crates.
- The host (macOS) build keeps working — `cargo check`/`cargo build` from
  `pgsleuth/` must not require nightly or a Postgres-dev install.
- The existing Docker flow (`docker compose up --build`) keeps loading the
  eBPF program against Postgres end-to-end.
- Single license: `Apache-2.0` everywhere, matching the rest of pgsleuth.
- One `cargo metadata` resolves every crate the project ships.

## Non-goals

- ❌ Archiving the POC repo (that's #20).
- ❌ Preserving git history across the repo boundary. See *History* below
  for why, and where the history still lives.
- ❌ Renaming any crate. The package names that downstream code already
  imports (`pgsleuth-ebpf-common`, `pgsleuth-ebpf-loader`, `pgsleuth-ebpf`,
  `pgsleuth-pg-ext`) stay as-is.
- ❌ Refactoring the crates beyond what the move strictly requires. Any
  code change inside a moved crate is out of scope for this PR.

## Layout

```
pgsleuth/crates/
├── pgsleuth-core/            # already here — Finding, Severity, Tier
├── pgsleuth-postgres/        # already here
├── pgsleuth-otel/            # already here
├── pgsleuth-cli/             # already here
├── pgsleuth-ebpf/            # NEW — kernel-side BPF program
├── pgsleuth-ebpf-common/     # NEW — no_std shared types
├── pgsleuth-ebpf-loader/     # NEW — userspace loader (aya)
├── pgsleuth-pg-ext/          # NEW — pgrx-built Postgres extension
└── xtask/                    # NEW — `cargo xtask build-ebpf`
```

### Naming choice — dir name == package name

The worklist's DoD describes the destination as
`pgsleuth/crates/{ebpf, ebpf-common, loader, pg-ext}/`. We deliberately
**don't** follow that literally. The existing convention in `crates/` is
`<package-name>/` (e.g. `crates/pgsleuth-core/` ↔ `package pgsleuth-core`).
Renaming the directories without renaming the packages would break that
convention. Renaming the packages would force a churn pass through every
import in the loader, every cargo doc reference, every changelog entry,
and `cargo-pgrx`'s symbol lookup (the embed binary name encodes the
package name verbatim — see `pgsleuth-pg-ext/Cargo.toml`).

The DoD shorthand was descriptive of the intent ("eBPF-related crates,
under `crates/`"), not a literal directory spec.

### xtask is in scope

The worklist DoD lists four crates; the POC ships five. The fifth, `xtask`,
is the build orchestrator the rust-dev container invokes via
`cargo xtask build-ebpf` (see `crates/xtask/src/main.rs`). It must come
along — without it, `infra/docker/build.sh` has no way to drive the kernel
crate build against `bpfel-unknown-none` from inside the container.

## Workspace integration

The pgsleuth root `Cargo.toml` grows in two coordinated places:

1. **`members`** — adds all five moved crates.
2. **`default-members`** — set for the first time, listing **only the
   host-buildable crates**:

   ```toml
   default-members = [
       "crates/pgsleuth-core",
       "crates/pgsleuth-postgres",
       "crates/pgsleuth-otel",
       "crates/pgsleuth-cli",
       "crates/pgsleuth-ebpf-common",
       "crates/pgsleuth-ebpf-loader",
       "crates/xtask",
   ]
   ```

   This mirrors the POC's pattern — plain `cargo check` from the workspace
   root only touches stable-buildable userspace crates, so the macOS host
   stays a usable dev environment. The kernel + extension crates are still
   addressable via `-p pgsleuth-ebpf` or `cargo xtask build-ebpf`.

### Profile coordination

The kernel crate's `[profile.dev]` / `[profile.release]` blocks are silently
ignored by Cargo on non-root workspace members (Cargo emits a warning and
uses the workspace's profile). The non-negotiable kernel requirement is
**`panic = "abort"`** — `bpfel-unknown-none` has no unwinding runtime.

Cargo also forbids overriding `panic` per-package. So `panic = "abort"`
goes on the workspace-root `[profile.release]`. Side effects:

- Slightly smaller release binaries for the userspace crates.
- `pgsleuth-cli` cannot use `std::panic::catch_unwind` in release builds.
  It currently doesn't; if a future feature needs it, revisit by carving
  the eBPF crate into a separate workspace with its own profile (the path
  not taken in this design).

The moved `pgsleuth-ebpf/Cargo.toml` drops its now-ignored `[profile.*]`
blocks to avoid the Cargo warning.

### Lints

Existing pgsleuth crates opt in to workspace lints (`[lints] workspace = true`,
which activates `clippy::pedantic` + `unsafe_code = "deny"`). The moved
crates **do not** opt in:

- `pgsleuth-ebpf` uses `unsafe` extensively — that's the nature of the
  kernel-side surface.
- `pgsleuth-pg-ext` interacts with pgrx-generated bindings that don't
  satisfy `clippy::pedantic` out of the box.
- The other moved crates are POC-grade and aren't ready for the strict
  gate; tightening them is follow-up work outside this PR.

Each moved crate's `Cargo.toml` therefore omits `[lints]`. When a crate
graduates to v0.1 quality we opt it in.

## License

POC: `MIT OR Apache-2.0`. Main: `Apache-2.0`. The original author is the
same person, so there is no permissions issue with narrowing the moved
crates to `Apache-2.0` via workspace inheritance
(`license.workspace = true`). Future external contributors sign the CLA
that goes with `Apache-2.0`. The POC repo retains its dual license
header until archival.

## Docker flow updates

```
infra/docker/docker-compose.yml      rust-dev.working_dir
  /workspace/source/pgsleuth-ebpf-poc/   →   /workspace/source/pgsleuth/

infra/docker/build.sh                first line `cd ...`
  cd /workspace/source/pgsleuth-ebpf-poc   →   cd /workspace/source/pgsleuth

infra/docker/README.md               "Container Details / rust-dev / Working dir"
infra/docker/rust-dev.Dockerfile     comment about pgrx version pin
```

`load-ebpf.sh` and `install-pg-ext.sh` reference target/-relative paths
only (resolved against the shared `/workspace/build` mount), so they need
no change.

## History

We do **not** rewrite history into pgsleuth via `git filter-repo` or
`subtree`. Reasons:

1. The POC repo is going to be archived (read-only) in #20. The full
   history remains discoverable there.
2. `filter-repo` would introduce a non-linear merge into pgsleuth's `main`
   and balloon the PR diff, making the *intent* (one-shot promotion)
   harder to review than the *outcome*.
3. The crates have less than two months of POC history; the cost of
   losing per-line `git blame` continuity is bounded.

Mitigation: this design note is the durable reference, plus the CLAUDE.md
update calls out the POC repo as the historical home. When archival
lands (#20), the POC repo's README will get a one-line redirect to the
in-tree location.

## Verification — what the PR has to prove

| Check                                                                             | Where         |
|-----------------------------------------------------------------------------------|---------------|
| `cargo check` from `pgsleuth/` (default members)                                  | macOS host    |
| `cargo test --workspace`* + `cargo clippy --workspace --all-targets -- -D warnings` (excluding kernel + extension via `--exclude`) | rust-dev container |
| `cargo xtask build-ebpf` produces `target/bpfel-unknown-none/release/pgsleuth-ebpf` | rust-dev container |
| `cargo pgrx package -p pgsleuth-pg-ext` produces the staged install tree          | rust-dev container |
| `docker compose -f infra/docker/docker-compose.yml up --build` end-to-end: loader attaches against Postgres, extension installs, smoke-test SQL works | full compose flow |

\* `--workspace` does include the excluded-by-default crates. The
verification command therefore either drops `--workspace` (covers
default-members) or uses
`--workspace --exclude pgsleuth-ebpf --exclude pgsleuth-pg-ext` to be
explicit about scope.

## How we'll know this layout is wrong

- **Per-package profile divergence becomes unmanageable.** If a future
  crate needs `panic = "unwind"` while the kernel crate still needs
  `panic = "abort"`, split the eBPF crate into its own workspace (the
  shape the POC had).
- **`default-members` keeps growing exclusions.** If more than two crates
  need to be excluded from the host build, that's a signal the workspace
  should be split into `pgsleuth-host` and `pgsleuth-linux` workspaces.
- **Single-license becomes a contribution blocker.** If outside
  contributors push back on `Apache-2.0`-only, revisit; dual licensing is
  not architectural, just a footer.
