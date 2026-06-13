# Six Postgres alarms, one eBPF program, zero superuser queries

> *Build log for pgsleuth Tier 1: the foundation, the skeleton, the
> reuse pattern, and what we deferred.*
> Posted 2026-06-13.

We just shipped Tier 1 of [pgsleuth](https://github.com/TarqWork/pgsleuth)
— six catalog alarms, four collectors, the Cargo workspace, an eBPF
program with five attach points, an OTLP log + metric pipeline, and
a reference Grafana panel. End-to-end. Sixteen merged PRs over the
course of a few days of focused work.

This post is the build log. It's deliberately not a "look how clever we
are" piece — it's the story of which v0 corners we cut, where the
pipeline-reuse pattern paid off, and what's left for v0.1.

## The shipped alarms

| # | Alarm | Tier | Detection | What it does |
|---|---|---|---|---|
| **#43 ★** | Fsync Jitter | T3 (eBPF) | `block:block_rq_issue` + `block:block_rq_complete` correlated by `(dev, sector)` | Bucket per-IO latency into a histogram per WAL device; fire when P50 > threshold for N consecutive 1-s intervals |
| **#46 ★** | Checkpoint Storm | T1 (polling) | `pg_stat_checkpointer` + `pg_stat_wal` deltas | Classify each interval into one of four buckets (write-phase / sync-phase / forced / FPW-flood); fire on dominant-pattern recurrence |
| **#47 ★** | Temp-File Spill — Capacity | T1 (polling) | `walkdir` over `$PGDATA/base/pgsql_tmp/` + `statvfs` | Fire when footprint > threshold OR free < threshold |
| **#44 ★** | Connection Storm | T1 (polling) | `pg_stat_activity` client-backend count | Fire when count > threshold for N consecutive intervals |
| **#48 ★** | Cgroup CPU Throttling | T1 (polling) | cgroup v2 `cpu.stat` deltas | Fire when `throttled_usec` delta exceeds threshold ms/sec sustained |
| **#45 ★** | Temp-File Spill — Per-Query | T3 (eBPF) | `syscalls:sys_enter_openat` + `unlinkat` | Detect any `pgsql_tmp/...` open from the postmaster's PID tree; emit per (pid, path) once |

Plus four collectors (`pg_stat_statements`, `pg_stat_activity`,
`pg_stat_checkpointer`, `cpu.stat`) and the foundation work — workspace,
OTel emitter, eBPF kernel correlation, dev_t parsing for the WAL
device, the Postgres extension that resolves WAL device + postmaster
PID at startup, the pg_stat_statements-friendly read-only role.

## The pipeline-reuse pattern

The whole Tier 1 plan was structured around one investment: build
**#43** (the fsync-jitter skeleton) properly, then *reuse* the pipeline
for every other alarm. That meant doing four things on the first alarm
that we'd otherwise have to redo five more times:

1. **Wire types** in `pgsleuth-ebpf-common` for the userspace ↔ kernel
   boundary — `BlockEvent`, `BlockIoLatencyEvent`, `RqKey`, plus a
   `FilterConfig` shared by all probes (PID / cgroup_id / comm / dev_t).
2. **OTLP** pipeline in `pgsleuth-otel` — a log `Emitter` for findings,
   a sibling `MetricsEmitter` with named histograms for the
   `pgsleuth.wal.io.latency` series. Both fail gracefully when there
   is no collector endpoint — operators get findings as `tracing`
   logs and we don't lose signal.
3. **A `ConsecutiveBreachCounter`** in `pgsleuth-core` — the "fire after
   N consecutive intervals" pattern that lives in three of the six
   alarms. Once it was generic, the per-alarm code was thin.
4. **The `Finding` envelope** — `schema_version` + `rule_version`
   distinct, evidence as `serde_json::Value`, remediation with text
   + knob list. The Postgres brain (deferred) reads this; the
   "tripwire" attribute `pgsleuth.mapping.version` is on every emitted
   record so downstream collectors detect the shape change without
   reading docs.

Once #43 was in, the remaining ★ alarms averaged about 200 lines of
new Rust each. The "alarm" became *"add a CLI subcommand, write a
polling loop, plug into the existing `Emitter`, fire a `Finding` with
the right `rule_id` and evidence shape."* That is the pattern we
wanted.

## What we deferred (and where it goes)

A v0 *skeleton* by name has to defer real things. We did:

- **The rule engine** (#28). Everything that fires Findings today does
  it inline in the alarm's CLI subcommand. Design doc 001 pins the YAML
  rule schema + named evaluator pattern. When the engine ships, each
  inline rule becomes one YAML file and one `Evaluator` impl. None of
  the wire types change.
- **The eBPF half of #44 (Connection Storm).** The catalog spec is a
  split detector — backend count AND `sched_switch`/`inet_csk_accept`
  churn. v0 ships the polling half. The Finding evidence carries
  `churn_observed = false` so the brain can tell the halves apart.
- **The eBPF half of #48 (Cgroup throttling).** Polling `cpu.stat` is
  load-bearing on managed K8s anyway (the [k8s-ebpf-caveats doc](docs/research/k8s-ebpf-caveats.md)
  walks through which operators can and can't grant `CAP_BPF` /
  `CAP_PERFMON`). The eBPF kprobes on `throttle_cfs_rq` /
  `unthrottle_cfs_rq` add per-window timing fidelity where the caps
  are grantable.
- **The uprobe attribution layer for #45.** The syscall tracepoint
  surfaces *which file* spilled, but `bytes_spilled` and `query_hash`
  need uprobes on `BufFileCreateTemp` and the query-bracketing
  functions. v0's `TempFileEvent` has fields for both, set to 0; the
  uprobe layer fills them in without breaking the wire.
- **A live OTLP collector wired into the compose fixture.** Findings
  fire end-to-end through the SDK pipeline; the collector hook is one
  config away. The Grafana panel at [`dashboards/wal-io-latency.json`](dashboards/wal-io-latency.json)
  is the operator-side rendering target once that lands.

## The non-obvious details

A few choices that ended up mattering more than expected:

### Docker overlay vs. the kernel's dev_t

`pgsleuth_wal_device()` in the Postgres extension calls
`std::fs::metadata().dev()` on `$PGDATA/pg_wal` and pretty-prints it
as `major:minor` using `libc::major`/`minor`. On the v0 fixture
(Docker Desktop), this returns **254:1**. The kernel's
`block:block_rq_issue` tracepoint reports the actual underlying
block device as **254:0** — off by 1 in the minor.

That's not a bug. It's the overlay filesystem's synthetic `st_dev`
versus the underlying whole-disk dev. On bare metal with `$PGDATA`
on a real volume, the two agree. On Docker overlay they don't, and
the loader exposes a `--dev-t <value>` override so the operator can
pin a known-good value. We documented it loud in #18 and shipped.

### The kernel encodes dev_t differently than glibc

The string `"254:1"` becomes `(254 << 20) | 1 = 266338305` for the
kernel's block-layer tracepoint format. glibc's `makedev` uses a
different bit split entirely. The loader has a tiny
`parse_kernel_dev_t` function that does the conversion; four unit
tests cover whitespace, field overflow, and the obvious round-trip.

### Read-only role, not superuser

The pg-fixture (#10) creates `pgsleuth_agent` with `pg_monitor` +
`pg_read_all_stats` — and the collectors verify they only use the
public catalog views. We hit one bug there: the original
`pg_stat_statements` query joined `pg_authid` for `rolname`. That's
**superuser-only**. Switched to `pg_roles` (public view) and the
unprivileged role can run it. The architectural invariant "the agent
is read-only" is now enforced at the *role* level on the fixture,
not just by promise.

### tracefs is not a bind mount

The first time we tried to attach a kernel tracepoint with aya, the
attach failed with `"tracefs not found"`. We mounted `/sys/kernel/tracing`
into the container — and got an empty directory. Bind-mounting tracefs
doesn't expose its contents; it has to be mounted *inside* the
container. `setup-postgres.sh` now does `mount -t tracefs tracefs
/sys/kernel/tracing` at boot. `CAP_SYS_ADMIN` was already in the
grant list for bpffs, so we got it for free.

### Capability tightening: only what's needed

The `pgsleuth-ebpf-poc` cap set included `CAP_NET_ADMIN`. None of the
v0 probes touch the network — they're all block-layer, syscall, or
file-system. We dropped `NET_ADMIN` in #40 and verified every probe
still attaches under `BPF + PERFMON + SYS_ADMIN`. `NET_ADMIN` comes
back when the eBPF half of #44 (`sched_switch` + `inet_csk_accept`)
lands. The new [capability matrix doc](docs/research/ebpf-capabilities.md)
walks through per-environment availability so operators can predict
which tier their cluster supports.

## What this proves

The catalog's central bet was: a single eBPF program with a few well-chosen
attach points + a polling collector layer is enough to express the
six most important Postgres alarms — including the ones that look
like they should each need a separate detector. The reuse cost on
each new alarm after #43 was small enough that the next milestone
(rule engine + the Tier-2 cloud-API alarms) won't have to rebuild
the plumbing.

The wire format ([`Finding`](crates/pgsleuth-core/src/finding.rs))
hasn't changed shape since the first commit. We bumped
`FINDING_SCHEMA_VERSION` once (it's 1). The brain consumes the same
JSON envelope from any of the six alarms.

## What's next

In rough order:

1. **The rule engine** (#28) — convert each inline v0 rule into a YAML
   manifest + named evaluator. None of the existing alarms change shape.
2. **Tier-2 collectors** — CloudWatch (for `auto_explain` log
   capture on RDS), Cloud SQL Query Insights on GCP, the Azure Monitor
   equivalent. The matrix is in [`docs/research/managed-pg-data.md`](docs/research/managed-pg-data.md).
3. **The eBPF halves we deferred** — connection storm sched probes,
   cgroup throttle kprobes, uprobe attribution for the temp-file
   alarm. None of these change the existing wire types.
4. **The brain.** Findings get explained in plain English for the
   operator. The model interface is the JSON envelope and nothing else.
5. **CI** (#1) — wire `make ci` to GitHub Actions. We have 50+ unit
   tests in tree and an end-to-end Docker smoke that each PR ran
   against by hand. Time to automate.

The repo is at [github.com/TarqWork/pgsleuth](https://github.com/TarqWork/pgsleuth).
Issues and PRs are open. The catalog lives at
[`docs/research/Database Observability Alarms.md`](docs/research/Database%20Observability%20Alarms.md)
— it's the source of truth and the next 16 alarms are documented
there too.

— *Built with [Claude Code](https://claude.com/claude-code) over a
focused session. The build log here is the same one the agent kept
while shipping. Both halves of the partnership do better work than
either does alone.*
