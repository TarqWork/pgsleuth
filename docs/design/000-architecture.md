# 000 — Architecture

| | |
|---|---|
| Status | Draft |
| Author | @gagan (TODO: github handle) |
| Created | 2026-04-29 |
| Last revised | 2026-04-29 |
| Supersedes | none |

## Problem

Operating Postgres in production is observability-poor relative to its capability. The data is there — `pg_stat_statements`, `pg_stat_io`, `pg_locks`, `pg_stat_replication`, `auto_explain` output, and on Linux, kernel-level signals reachable via eBPF — but the tools that surface it are split into three unsatisfying camps:

1. **Raw SQL views.** `pg_stat_statements` is powerful and inscrutable. Operators paste fragments into Slack and ask each other what to look at.
2. **Commercial SaaS.** pganalyze, Datadog DBM, SolarWinds DPA. Capable but pricey, dashboard-heavy, and force you to send query data to a third party. Many regulated environments (fintech, healthcare, government) cannot use them at all.
3. **Older OSS.** pgBadger (log-only, dated), pgHero (single-instance, light), PMM (dashboard-heavy, no diagnosis intelligence), pg_activity (live-only).

No project today combines: LLM-assisted diagnosis (so the operator gets *answers*, not metrics), local-first execution (so regulated environments can use it), and OpenTelemetry-native output (so it integrates with the observability stack the team already has). That's the gap.

## Goals

- Ship a v1.0 OSS Postgres observability agent in 24 weeks with real production users.
- Diagnose performance issues with structured rules, then have an LLM explain findings in operator-readable language.
- Output everything via OpenTelemetry — emit to whatever backend the user already has.
- Run with bounded, low overhead in production.
- Be deployable in regulated environments by defaulting to a local LLM.

## Non-goals (until v1.0)

- ❌ MySQL, MongoDB, or any other database. Postgres only.
- ❌ Custom TSDB, custom dashboards, custom alerting. We emit OTel and stop.
- ❌ Hosted SaaS during the OSS build phase. A paid hosted "Cloud-Enhanced" tier is planned post-v0.2 — it will not gate OSS features.
- ❌ Public advertising before v0.2. Repo is public from week 1; no HN, Twitter, blog launch until the LLM plan-explainer demo is shippable.
- ❌ Auto-remediation. The LLM does not run `ALTER TABLE`. Read-only role, advisory output only. This is enforced architecturally, not by policy.
- ❌ Premature abstraction. Build for one DB, design for two, ship for three.

## Architecture

### The tier model

pgsleuth runs in three modes, each adding capability without losing the floor:

- **Tier 1 — standard.** Postgres views only (`pg_stat_*`, `pg_locks`, `pg_stat_activity`). On-demand `EXPLAIN (ANALYZE, BUFFERS)`. Works on RDS, Aurora, Cloud SQL, self-managed. The floor every install gets.
- **Tier 2 — cloud-enhanced.** Adds the cloud provider's monitoring/logging API: CloudWatch Logs (for `auto_explain`), RDS Performance Insights, Cloud SQL Query Insights, Cloud Logging. Managed Postgres only. Implemented in v1.0.
- **Tier 3 — deep.** Adds eBPF-assisted host sampling for syscall and I/O attribution per backend process. Self-managed only. Implemented in phase 5.

Each rule declares its tier and its `min_pg_version`. Rules that need tier 2 or tier 3 data are skipped on installs that don't have it; the UI surfaces a clear "limited mode" indicator. Graceful degradation is a first-class concept from day one — not bolted on later.

### The component split

```
┌──────────────────────────────────────────────────────────────┐
│                    Postgres instance(s)                       │
│   pg_stat_statements │ auto_explain │ pg_stat_io │ pg_locks  │
└──────┬──────────────────────────────────────┬────────────────┘
       │ SQL polling (RO role)                │ host-only signals
       ▼                                      ▼
┌──────────────────────┐         ┌────────────────────────────┐
│ Tier 1 collector     │         │ Tier 3 collector           │
│ Postgres views       │         │ eBPF (aya), /proc, etc.    │
│ Works EVERYWHERE     │         │ Self-managed only          │
└──────┬───────────────┘         └────────────┬───────────────┘
       │                                      │
       │           ┌──────────────────────────┤
       │           │ Tier 2 collector         │
       │           │ Cloud APIs (CloudWatch,  │
       │           │ Cloud Logging, RDS PI)   │
       │           └────────────┬─────────────┘
       │                        │
       └────────────┬───────────┘
                    ▼
        ┌──────────────────────────┐
        │ pgsleuth-agent (Rust)    │
        │ Sampler + normalizer +   │
        │ workload fingerprinting  │
        │ + rule engine            │
        │ → emits Findings         │
        └────────────┬─────────────┘
                     │ Findings (JSON)
                     ▼
        ┌──────────────────────────┐
        │ pgsleuth-brain (Python)  │
        │ LLM router + agents      │
        │ NO database access       │
        │ Reads findings, emits    │
        │ explanations             │
        └────────────┬─────────────┘
                     │ OTLP
                     ▼
            OTel collector → Grafana / Prometheus / Datadog
```

### The two non-negotiable principles

**1. The brain never touches the database.** The agent is the only component with database access. The rule engine emits structured `Finding` objects (`crates/pgsleuth-core/src/lib.rs`). The brain consumes findings as JSON and returns prose. The LLM has no tool to query Postgres directly — not because we forbid it by policy, but because there is no such tool wired up. This is the safety guarantee.

**2. The wire format between agent and brain is OTel/JSON only.** No shared types between Rust and Python. No cross-language Pydantic models. No magic. This is the only way the two-stack split stays manageable for a solo developer over 24 weeks.

### Stack

| Layer | Choice | Reasoning |
|---|---|---|
| `pgsleuth-agent` | Rust (Cargo workspace) | Performance, eBPF via `aya`, depth signal, ecosystem (`tokio-postgres`) |
| `pgsleuth-brain` | Python (async) | LLM tooling ecosystem; Rust's LLM story isn't there yet |
| Wire format | OTLP / OTel | Standard, no lock-in, plug into any backend |
| Storage | None | Emit to user's existing TSDB |
| LLM default | Local Ollama (Llama / Qwen) | Privacy, cost, OSS coherence |
| LLM opt-in | Anthropic, OpenAI, Google | Power users, frontier reasoning |
| License | Apache 2.0 | Maximize adoption and credibility |

Cargo workspace layout: `pgsleuth-core`, `pgsleuth-postgres`, `pgsleuth-otel`, `pgsleuth-cli`. Allows future MySQL crate without forcing the abstraction now.

### What's in v0.1, v0.2, v1.0

- **v0.1** (week 6) — Tier 1 collector for `pg_stat_statements` and `pg_stat_activity`, ~10 deterministic rules, OTel emit, Grafana board. No LLM yet.
- **v0.2** (week 10, public launch) — `auto_explain` capture (self-managed), plan-explanation agent in the brain, Ollama default. This is the demo: paste a slow query, get a plain-English diagnosis with structured remediation suggestions.
- **v1.0** (week 24) — workload fingerprinting, index recommender, lock diagnostician, eBPF sampling, Tier 2 cloud adapters, conference talks, real production users.

## Alternatives considered

**Postgres extension (via `pgrx`).** Considered: an extension can see things `pg_stat_*` can't (per-query waits, internal counters). Rejected for v1.0: extensions are a much bigger commitment to packaging, ops, and cross-version compatibility, and they don't run on managed Postgres which is our v1 audience. Possible v2.

**Single language (Rust everywhere or Python everywhere).** Considered. Rust everywhere: the LLM ecosystem in Rust is immature; `langchain-rs` and equivalents are fine for hobby work but not for production agentic systems yet. Python everywhere: gives up the depth signal and the eBPF path. The split has a real maintenance tax (acknowledged), mitigated by (a) the OTel-only wire format, (b) the unified `Makefile`, (c) the rule that there are no shared types between languages.

**Building a dashboard.** Tempting and rejected. Every existing Postgres tool has a dashboard. None of them are better than Grafana + the right datasource. By emitting OTel we let the user keep the UI they already trust.

**LLM-driven query execution.** Some recent demos give an LLM a Postgres connection and let it run `EXPLAIN`, schema queries, etc. autonomously. Rejected for safety reasons. Even read-only LLM-driven query execution can leak data, run expensive scans, and confuses the audit story. The agent runs structured queries; the brain reasons over the structured output.

**Selling the OSS as commercial-only (BSL or proprietary).** Considered. Rejected for credibility reasons — the audience we're targeting (Postgres community, principal engineers, OSS maintainers) reads BSL as a smell. Apache 2.0 with a paid hosted layer post-v0.2 is the cleaner path.

## Open questions

These are deliberately unresolved. Phase 0 spikes and the 5 DBA conversations should answer them by end of week 2.

1. **Managed Postgres data access — what's actually possible.** RDS / Aurora / Cloud SQL restrict `auto_explain` log access to CloudWatch / Cloud Logging. How rich is the data via those APIs? What's the latency? What's the cost? **→ Spike output: [`docs/research/managed-pg-data.md`](../research/managed-pg-data.md)**

2. **eBPF feasibility on the target environments.** Does `aya` work on the Linux versions our users run? What capabilities are required? Is Postgres-on-Kubernetes (CNPG, Zalando, Crunchy) instrumentable, or do those pods lack the privileges? **→ Spike output: [`docs/research/ebpf-feasibility.md`](../research/ebpf-feasibility.md)**

3. **LLM cost ceiling.** At what query volume does even the local-first design start hurting? Is there a workload-fingerprinting threshold below which the LLM never gets called? **→ Phase 3 question; flag here.**

4. **Schema privacy in RAG.** If we RAG over the user's schema for plan explanation, where does the schema live? Local file? Vector DB? This is a real privacy decision and the answer shapes the architecture. **→ Phase 2 question; flag here.**

5. **Rule schema and rule-engine architecture.** What's the data model for a rule? Pure data (YAML/JSON) or code? How are rules version-gated against Postgres versions? **→ Phase 1 question; design doc 001 will resolve this.**

6. **Cloud observability blueprints — is OTel-only output enough?** [Google has just published Agent Observability + the agentic blueprint at Next '26](https://cloud.google.com/blog/topics/google-cloud-next/google-cloud-next-2026-wrap-up), AWS has [CloudWatch + Application Signals with native OTLP in preview](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-OpenTelemetry-Sections.html), and Azure has [Monitor + Application Insights with an opinionated OTel distro](https://learn.microsoft.com/en-us/azure/azure-monitor/app/opentelemetry). Our position is OTel-native and stop — but do these blueprints expect specific resource attributes, semantic conventions beyond the [OTel DB spec](https://opentelemetry.io/docs/specs/semconv/database/), log/trace correlation IDs, or first-party export shapes that pure OTLP doesn't cover by default? Risk: a regulated user on GCP/AWS/Azure adopts pgsleuth, then finds that their managed observability stack doesn't ingest our signal cleanly without an adapter we didn't build. **→ Week-1 research task; audit each cloud's current blueprint and decide: (a) OTel suffices, (b) OTel + a thin per-cloud attribute mapping suffices, or (c) we need first-class exporters per cloud. Document in [`docs/research/cloud-observability-blueprints.md`](../research/cloud-observability-blueprints.md).**

## How we'll know if this is the wrong architecture

Concrete signals that would force a redesign:

- The OTel-only wire format is too lossy and we keep wanting to leak structured types across the boundary. Mitigation: define a canonical `Finding` JSON schema and version it.
- The two-language split costs more than expected. If by week 8 the dev loop across both stacks is taking >30% of building time, fold the brain into Rust (sacrificing the LLM ecosystem advantage) or fold the agent into Python (sacrificing the eBPF advantage) — whichever loses less. The decision goes in design doc 002 if it happens.
- Tier 2 turns out to be the *primary* product for the v1 audience (managed Postgres) and Tier 1 is too thin to be useful on its own. If true, accelerate Tier 2 from v1.0 into phase 2.
- eBPF turns out to be infeasible on Postgres-on-K8s (which is a large fraction of self-managed). If true, Tier 3 becomes "Linux VM only" with a clear caveat.
