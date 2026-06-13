# pgsleuth

> The Postgres observability tool that thinks like a senior DBA, runs locally, and refuses to lock you in.

**Status: pre-alpha. Building in public. No support yet.**

**v0 milestone shipped (2026-06-13):** Tier-1 catalog alarms end-to-end. Six alarms across polling + eBPF, four Postgres collectors, an OTLP log + metric pipeline, a reference Grafana panel. See *What works today* below. The brain (LLM-side explanation) is still deferred — Findings ride OTLP today; plain-English diagnosis lands at v0.2.

pgsleuth is an OSS, self-hosted Postgres observability agent that uses local-first LLMs to diagnose performance issues, explain query plans in plain English, and recommend fixes — emitting everything via OpenTelemetry so it plugs into existing Grafana / Prometheus / Datadog stacks without lock-in.

## The thesis

The Postgres observability market has clear incumbents (pganalyze, Datadog DBM, SolarWinds DPA) and clear OSS gaps (`pg_stat_statements` is raw, pgBadger is dated, PMM is dashboard-heavy with no intelligence). No credible OSS project today combines:

1. **LLM-native diagnosis** (local-first via Ollama, frontier models opt-in)
2. **OpenTelemetry-native output** (no proprietary dashboard, no lock-in)
3. **Production-grade collection** (eBPF-assisted, low overhead)

That's the gap pgsleuth fills.

## What works today

Six [catalog](docs/research/Database%20Observability%20Alarms.md) alarms ship as v0 skeletons. Each emits a `Finding` log record on the OTLP pipeline ([`pgsleuth-otel::Emitter`](crates/pgsleuth-otel/src/lib.rs)); the WAL-IO histogram also rides as an OTel metric ([`MetricsEmitter`](crates/pgsleuth-otel/src/metrics.rs)). All rules currently live inline in their CLI subcommands; they graduate into YAML manifests when the rule engine ([#28](https://github.com/TarqWork/pgsleuth/issues/28)) lands.

- **Fsync Jitter** — Pairs `block:block_rq_issue` + `block:block_rq_complete` tracepoints to bucket per-IO latency on the WAL device into a histogram and fires when P50 exceeds the configured threshold for N consecutive intervals. Code: [`pgsleuth-ebpf`](crates/pgsleuth-ebpf/src/main.rs) + [`pgsleuth-ebpf-loader`](crates/pgsleuth-ebpf-loader/src/main.rs). Grafana panel: [`dashboards/wal-io-latency.json`](dashboards/wal-io-latency.json).

- **Checkpoint Storm (classified)** — Polls `pg_stat_checkpointer` + `pg_stat_wal`, classifies each interval into write-phase / sync-phase / forced / FPW-flood, and fires only on dominant-pattern recurrence with the catalog-recommended config knob in the Finding payload. Code: [`pgsleuth-postgres::stat_checkpointer`](crates/pgsleuth-postgres/src/stat_checkpointer.rs) + [`pgsleuth-cli checkpoint-storm`](crates/pgsleuth-cli/src/checkpoint_storm.rs).

- **Connection Storm** — Polls `pg_stat_activity` for the live client-backend count and fires when it exceeds threshold for N consecutive intervals. The eBPF churn half (`sched:sched_switch`, `inet_csk_accept`) is deferred to the rule engine; the Finding evidence carries `churn_observed=false` so the brain can tell the halves apart. Code: [`pgsleuth-cli connection-storm`](crates/pgsleuth-cli/src/connection_storm.rs).

- **Cgroup CPU Throttling** — Polls cgroup-v2 `cpu.stat`, computes the per-interval `throttled_usec` delta, and fires when throttle time exceeds a sustained ms-per-second threshold. The eBPF kprobe pair on `throttle_cfs_rq` / `unthrottle_cfs_rq` is deferred; polling is the load-bearing detector on managed K8s anyway per [the caveats matrix](docs/research/k8s-ebpf-caveats.md). Code: [`pgsleuth-cli cgroup-throttle`](crates/pgsleuth-cli/src/cgroup_throttle.rs).

- **Temp-File Spill — Capacity (SRE)** — `du`-equivalent walk of `$PGDATA/base/pgsql_tmp/` + `statvfs()` on the mount; fires when aggregate footprint > threshold OR free space < threshold. Single-fire latch suppresses duplicates during a sustained breach. Code: [`pgsleuth-cli temp-spill`](crates/pgsleuth-cli/src/temp_spill.rs).

- **Temp-File Spill — Per-Query Attribution (eBPF)** — Tracepoints on `syscalls:sys_enter_openat` / `unlinkat` detect any `pgsql_tmp/` file creation from the postmaster's PID tree and emit a Finding once per unique (pid, path). The `BufFileCreateTemp` uprobe for byte counting + query-hash attribution is deferred; the [`TempFileEvent`](crates/pgsleuth-ebpf-common/src/lib.rs) wire shape already has slots for both. Code: kernel side in [`pgsleuth-ebpf`](crates/pgsleuth-ebpf/src/main.rs), userspace in [`pgsleuth-ebpf-loader`](crates/pgsleuth-ebpf-loader/src/main.rs).

The four supporting collectors (`pg_stat_statements`, `pg_stat_activity`, `pg_stat_checkpointer`, `cpu.stat`) live under [`crates/pgsleuth-postgres/`](crates/pgsleuth-postgres/src/) and [`crates/pgsleuth-cli/src/cgroup_throttle.rs`](crates/pgsleuth-cli/src/cgroup_throttle.rs). The Postgres extension that resolves the WAL device + postmaster PID at startup is at [`crates/pgsleuth-pg-ext/`](crates/pgsleuth-pg-ext/src/lib.rs). Capability set used at runtime (and rationale per environment) is in [`docs/research/ebpf-capabilities.md`](docs/research/ebpf-capabilities.md).

## Tier model

pgsleuth runs in three modes, each adding capability without losing the floor:

- **Tier 1 — standard.** Postgres views only (`pg_stat_*`, `pg_locks`, `pg_stat_activity`). Works on RDS, Aurora, Cloud SQL, self-managed.
- **Tier 2 — cloud-enhanced.** Adds CloudWatch Logs / Cloud Logging integration to capture `auto_explain` output and Performance Insights / Query Insights data. Managed Postgres only. _v1.0._
- **Tier 3 — deep.** Adds eBPF-assisted host sampling for syscall + I/O attribution. Self-managed only. _Phase 5._

The brain consumes structured findings regardless of tier.

## Safety architecture

The LLM never touches the database. The agent reads Postgres via a read-only role; alarm rules emit structured Findings (today inline per-alarm; later via the [rule engine](docs/design/001-rule-schema.md)); the brain consumes Findings as JSON and returns prose. This is enforced architecturally, not by policy.

```
Postgres (RO role) ──► Agent (Rust) ──findings──► Brain (Python + LLM) ──► OTel
                       Rule engine                Never sees the database
```

## Stack

| Layer | Choice |
|---|---|
| Agent | Rust (Cargo workspace) |
| Brain | Python (async) |
| Wire format | OTLP / OTel |
| Storage | None — emits to your TSDB |
| LLM default | Local Ollama |
| LLM opt-in | Anthropic, OpenAI, Google |

## Roadmap

24 weeks to v1.0. See [`docs/design/000-architecture.md`](docs/design/000-architecture.md) for the full plan.

| Phase | Weeks | Status | Deliverable |
|---|---|---|---|
| 0 — Research & validation | 1–2 | ✅ done | Spikes (eBPF, managed PG data), design doc, 5 DBA conversations |
| 1 — Skeleton agent | 3–6 | ✅ done | Rust agent, Tier-1 catalog alarms (eBPF + polling), OTLP pipeline, reference Grafana panel. **v0.1.** |
| 2 — Plan capture + LLM explainer | 7–10 | next | `auto_explain` capture, plan-explanation agent. **v0.2 — public launch.** |
| 3 — Rule engine + workload fingerprinting | 11–14 | | YAML rule manifests ([design 001](docs/design/001-rule-schema.md)), cluster queries by plan shape, regression detection |
| 4 — Index recommender + lock diagnostician | 15–19 | | Two agentic workflows. **v0.5.** |
| 5 — eBPF deepening | 20–22 | partly early | Per-query uprobe attribution layer, sched/network probes deferred from Phase 1 alarms |
| 6 — Polish, docs, talks | 23–24 | | **v1.0.** |

eBPF sampling moved earlier than planned because four of the six Phase-1 alarms needed it. The Phase-5 line item now covers the *uprobe attribution layer* (byte counting, query-hash binding) and the network-side probes that were deferred from #44 / #48.

## License

Apache 2.0. See [LICENSE](LICENSE).

A hosted commercial tier is planned post-v0.2. The OSS agent will remain fully featured under Apache 2.0 — no community/enterprise split, no rules gated behind a paywall.

## Domain

`TODO(domain)` — to be registered.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pre-alpha — feedback and design-doc reviews welcome; code contributions deferred until v0.2.

## Pointers

- [Architecture design doc](docs/design/000-architecture.md)
- [Research notes](docs/research/) — phase 0 spike outputs
- [Blogs](blogs/) — long-form posts as they're written
