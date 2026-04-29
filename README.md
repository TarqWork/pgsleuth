# pgsleuth

> The Postgres observability tool that thinks like a senior DBA, runs locally, and refuses to lock you in.

**Status: pre-alpha. Building in public. No support yet.**

pgsleuth is an OSS, self-hosted Postgres observability agent that uses local-first LLMs to diagnose performance issues, explain query plans in plain English, and recommend fixes — emitting everything via OpenTelemetry so it plugs into existing Grafana / Prometheus / Datadog stacks without lock-in.

## The thesis

The Postgres observability market has clear incumbents (pganalyze, Datadog DBM, SolarWinds DPA) and clear OSS gaps (`pg_stat_statements` is raw, pgBadger is dated, PMM is dashboard-heavy with no intelligence). No credible OSS project today combines:

1. **LLM-native diagnosis** (local-first via Ollama, frontier models opt-in)
2. **OpenTelemetry-native output** (no proprietary dashboard, no lock-in)
3. **Production-grade collection** (eBPF-assisted, low overhead)

That's the gap pgsleuth fills.

## Tier model

pgsleuth runs in three modes, each adding capability without losing the floor:

- **Tier 1 — standard.** Postgres views only (`pg_stat_*`, `pg_locks`, `pg_stat_activity`). Works on RDS, Aurora, Cloud SQL, self-managed.
- **Tier 2 — cloud-enhanced.** Adds CloudWatch Logs / Cloud Logging integration to capture `auto_explain` output and Performance Insights / Query Insights data. Managed Postgres only. _v1.0._
- **Tier 3 — deep.** Adds eBPF-assisted host sampling for syscall + I/O attribution. Self-managed only. _Phase 5._

The brain consumes structured findings regardless of tier.

## Safety architecture

The LLM never touches the database. The agent reads Postgres via a read-only role, the rule engine emits structured findings, the brain consumes findings as JSON and returns prose. This is enforced architecturally, not by policy.

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

| Phase | Weeks | Deliverable |
|---|---|---|
| 0 — Research & validation | 1–2 | Spikes (eBPF, managed PG data), design doc, 5 DBA conversations |
| 1 — Skeleton agent | 3–6 | Rust agent, Tier 1 collectors, OTel emit, Grafana board. **v0.1.** |
| 2 — Plan capture + LLM explainer | 7–10 | `auto_explain` capture, plan-explanation agent. **v0.2 — public launch.** |
| 3 — Workload fingerprinting | 11–14 | Cluster queries by plan shape, regression detection |
| 4 — Index recommender + lock diagnostician | 15–19 | Two agentic workflows. **v0.5.** |
| 5 — eBPF sampling | 20–22 | Low-overhead syscall + I/O attribution via `aya` |
| 6 — Polish, docs, talks | 23–24 | **v1.0.** |

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
