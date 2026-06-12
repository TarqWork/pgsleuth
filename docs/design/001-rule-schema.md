# 001 — Rule schema and rule engine

| | |
|---|---|
| Status | Draft |
| Author | @gagan |
| Created | 2026-06-12 |
| Last revised | 2026-06-12 |
| Supersedes | none |
| Related | [`000-architecture.md`](000-architecture.md) |

## Problem

`000-architecture.md` settles the macro structure: a Rust agent emits structured
`Finding` objects, a Python brain consumes them as JSON, OTel is the only wire
format. It does **not** say what a *rule* is — the thing that turns sampled
Postgres + host data into a `Finding`. Every downstream task assumes this is
pinned down:

- The Cargo workspace (#22) lands `pgsleuth-core` with the `Finding` shape and
  rule traits the other crates depend on.
- The v0.1 deterministic rule pack (#28) needs a place to live.
- All six Tier-1 alarms (#43, #46, #47, #44, #48, #45) are rules. Three of them
  (#43, #46, #48) need a windowing model — "fires when commit latency > 10ms
  for >3 consecutive intervals" doesn't work as a stateless predicate.
- The brain (post-v0.2) consumes findings and must rely on a stable, versioned
  schema across rule revisions.

There is also a placeholder `Finding` struct in `crates/pgsleuth-core/src/lib.rs`
today. This doc replaces the open questions it papers over with concrete answers.

The five questions issue #21 asks us to resolve:

1. Rule data model — pure data, pure code, or hybrid?
2. How are rules version-gated against Postgres versions?
3. How are rules tier-gated (and gracefully skipped when a tier is missing)?
4. How does the engine evaluate rules?
5. What is the canonical `Finding` emission shape?

## Goals

- A rule schema that can express **every** Tier-1 catalog alarm without
  shoehorning. If we can't express the six `★` alarms, the schema is wrong.
- Authoring cheap enough that the v0.1 ten-rule pack is data, not code, for
  the simple cases.
- Graceful degradation: a rule whose required capability is absent is
  *skipped*, never errors. The user sees "limited mode" without losing the
  rules they *can* run.
- A `Finding` shape that maps cleanly onto an OTel Log Record so the agent
  doesn't have to maintain two representations.
- Version-gated rules — a rule that needs `pg_stat_io` (PG 16+) is silently
  excluded on PG 13 with a startup-log line.
- Schema-versioned findings — the brain can refuse or down-convert a future
  schema rather than crash.

## Non-goals (v0.1)

- ❌ Hot reload of rules. Restart the agent.
- ❌ User-authored rules through a UI or CLI. Rules ship in-tree until v0.2.
- ❌ A general-purpose CEP / streaming engine. The needed windowing is small
  and concrete (consecutive-interval counters, rolling histograms). We will
  not pull in a third-party CEP library.
- ❌ Cross-rule deduplication or alarm storming. Defer to v0.2 once we have
  field experience.
- ❌ Rule priorities or rule-to-rule dependencies. Each rule fires
  independently; the brain is responsible for narrative ordering.

## Architecture

### D1 — Data vs code: **hybrid, with data-first preference**

Rules are split into two cooperating halves:

1. **A YAML manifest** (data) — metadata, gating, thresholds, declarative
   predicate spec, and a reference to a Rust evaluator by name.
2. **A Rust evaluator** (code) — a typed handler that consumes normalized
   samples and returns `Option<Finding>` (or a stream of findings for
   windowed rules). The evaluator is the *only* thing that knows the
   rule's domain logic.

```yaml
# crates/pgsleuth-core/rules/replica_lag_high.yaml
id: replica.lag.high
version: 1
tier: 1
min_pg_version: 13
requires:
  - pg_stat_replication
evaluator: threshold_v1   # binds to a registered Rust evaluator
params:
  metric: pg_stat_replication.replay_lag_seconds
  op: ">"
  threshold: 60
window:
  kind: instant            # no windowing
severity: high
summary: "Replica {replica_id} lag {value}s exceeds {threshold}s"
remediation:
  text: "Investigate write volume on primary; check network between hosts"
```

The shared evaluators (`threshold_v1`, `consecutive_intervals_v1`,
`histogram_p95_v1`) cover the simple Tier-1 polling rules and the
"fires for N consecutive intervals" pattern. Anything more exotic — eBPF
join with `pg_stat_bgwriter` for the checkpoint classifier in #46,
syscall+uprobe attribution for #45 — gets a *bespoke* evaluator
(`checkpoint_classifier_v1`, `temp_spill_attrib_v1`) registered in
`pgsleuth-core` and selected by name in the YAML.

**Why hybrid.**

- *Pure data* breaks on rules like #43 (fsync jitter): the kernel-side BPF
  program emits a per-IO latency stream; the rule must keep a rolling
  histogram per device, compare P95 to a baseline, and require sustained
  breach. Encoding that in YAML invents a DSL nobody asked for.
- *Pure code* breaks on the catalog: the v0.1 deterministic rules (#28) are
  almost all "metric > threshold, severity X" shapes. Asking each to be a
  `fn` in Rust is repetition for no gain, and worse, it puts the catalog out
  of reach of non-Rust contributors.
- The hybrid lets a contributor add a "checkpoints_timed_ratio > 0.5" rule
  with one YAML file, while keeping the door open for an evaluator that
  needs every Rust escape hatch (eBPF ring buffer, async DB query,
  per-backend state).

**Storage.** Rule manifests live next to the crate that owns them:
`crates/pgsleuth-core/rules/*.yaml` for shared/catalog rules,
`crates/pgsleuth-postgres/rules/*.yaml` for collector-specific rules. They
are loaded at agent startup; no per-evaluation file I/O.

### D2 — Version gating: `min_pg_version` (+ optional `max_pg_version`)

Each rule declares `min_pg_version` as a major-version integer (e.g. `13`,
`16`). Optional `max_pg_version` for the rare case a rule applies only to a
deprecated path.

```yaml
min_pg_version: 16     # rule needs pg_stat_io
max_pg_version: ~      # no upper bound
```

At startup the agent queries `SHOW server_version_num` once per Postgres
target and computes the major version. The rule loader filters incompatible
rules out of the active set and logs:

```
[INFO] rule.replica.lag.high: enabled (pg 17)
[INFO] rule.io.read_latency.spike: skipped — needs pg ≥ 16, target is pg 14
```

No per-evaluation version re-check. If a target is rolling-upgraded under us
the next agent restart picks up the new rule set; we don't try to be clever
about hot version transitions.

### D3 — Tier gating: `tier` + `requires`

```yaml
tier: 3
requires:
  - ebpf.block_rq      # tracepoints block:block_rq_issue/complete
  - host.proc          # /proc readable
```

`tier` is the *headline* — what the user filters on. `requires` is the
*proof* — the concrete capabilities the rule needs the agent to have
discovered or negotiated.

Capability names are flat dotted strings in a fixed namespace:

- `pg_stat_statements`, `pg_stat_activity`, `pg_stat_io`,
  `pg_stat_replication`, `pg_stat_bgwriter` — Postgres extension/view names.
- `auto_explain.log` — the `auto_explain` log capture pipeline.
- `cloudwatch.auto_explain`, `cloud_logging.auto_explain` —
  per-cloud Tier-2 paths.
- `ebpf.block_rq`, `ebpf.sched_switch`, `ebpf.cgroup_throttle`,
  `ebpf.uprobe.postgres` — eBPF probe families.
- `host.proc`, `host.df`, `host.du` — non-eBPF host signals.

The agent's startup capability negotiation produces a `CapabilitySet`. The
rule loader filters: any rule with an unmet `requires` is skipped and listed
in the agent's startup log and in an OTel resource attribute
`pgsleuth.skipped_rules.count`. The user always sees what *they could have
gotten* on a richer install.

`tier` alone is not sufficient gating because a Tier-3 install on a host
without `CAP_BPF` for `cgroup_throttle` should still get the block-layer
rules. `requires` lets us be precise.

### D4 — Evaluation flow

```
┌──────────────────┐       ┌─────────────────┐
│ Tier 1 collector │──────►│ Sample (typed)  │
└──────────────────┘       └────────┬────────┘
┌──────────────────┐                │
│ Tier 2 collector │──────►         │
└──────────────────┘                ▼
┌──────────────────┐       ┌─────────────────┐
│ Tier 3 collector │──────►│  Rule engine    │
└──────────────────┘       │  (per-rule)     │
                           └────────┬────────┘
                                    │ Finding
                                    ▼
                           ┌─────────────────┐
                           │  OTel emitter   │
                           └─────────────────┘
```

Collectors push **typed samples** (not generic JSON) onto an in-process
channel. Each sample carries a kind (`PgStatStatementsRow`,
`WalIoLatency`, `CheckpointStat`, …) and a timestamp. The rule engine has
one task per active rule that subscribes to the sample kinds it needs.

Two evaluation modes:

- **Stateless / instant.** `window.kind: instant`. The evaluator runs on
  one sample at a time. Used by every simple-threshold rule.
- **Stateful / windowed.** `window.kind: consecutive_intervals` or
  `rolling_histogram`. The engine wraps the evaluator in a small windowing
  helper. `consecutive_intervals` covers #43 ("fires for 3 consecutive
  intervals"), #46 ("dominant-pattern recurrence"), and #48 ("sustained
  throttle"). `rolling_histogram` covers the P95-vs-baseline cases.

```yaml
window:
  kind: consecutive_intervals
  intervals: 3
  interval_ms: 10000
```

Bespoke evaluators that need richer state (a stream of per-IO records into a
per-device histogram, joined with a Postgres polling query) own their own
state in the Rust handler and ignore the YAML `window:` field. They declare
this with `window.kind: custom` so future readers can grep for it.

Concurrency: one async task per rule, fan-in from a single sample broker.
No locks across rules. A rule that hangs blocks only itself.

### D5 — `Finding` emission shape

The placeholder in `crates/pgsleuth-core/src/lib.rs` becomes:

```rust
/// Versioned diagnostic finding. Serialized as a single OTel Log Record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Schema version. Bump on breaking change so the brain can refuse
    /// or down-convert.
    pub schema_version: u32,

    /// Rule that fired (`replica.lag.high`).
    pub rule_id: String,
    /// Monotonic rule version — same `rule_id`, different `rule_version`
    /// means thresholds or semantics changed.
    pub rule_version: u32,

    pub tier: Tier,
    pub severity: Severity,

    /// When the rule decided to fire. Always UTC, RFC 3339.
    pub fired_at: chrono::DateTime<chrono::Utc>,

    /// Identifies the Postgres instance + cluster role.
    pub pg_instance: PgInstanceRef,

    /// Human-readable, *interpolated* summary. The brain may rewrite.
    pub summary: String,

    /// Structured evidence the rule used to decide. The brain reasons
    /// over this; OTel exporters drop it into the log record's body or
    /// attributes depending on size.
    pub evidence: serde_json::Value,

    /// Suggested remediation, structured.
    pub remediation: Remediation,

    /// Extra attributes the rule wants on the OTel log record itself
    /// (e.g. `db.name`, `pgsleuth.replica.id`).
    pub otel_attributes: BTreeMap<String, AttributeValue>,
}
```

`schema_version` and `rule_version` are distinct on purpose. The schema
version changes when the *envelope* changes (we add a required field, we
rename one). The rule version changes when *this rule's semantics or
thresholds* change. The brain can pin acceptable schema versions; the user
can correlate alarm history by rule version.

`PgInstanceRef`, `Remediation`, `AttributeValue` are also defined in
`pgsleuth-core` and intentionally narrow — see the worked example below.

**Mapping to OTel.** A `Finding` becomes one log record:

| `Finding` field | OTel log record placement |
|---|---|
| `fired_at` | `timestamp` |
| `severity` | `severity_text` + `severity_number` |
| `summary` | `body` |
| `evidence` | `body` (structured), or attribute `pgsleuth.evidence` if large |
| `rule_id`, `rule_version`, `schema_version`, `tier` | resource attributes (`pgsleuth.rule.id`, …) |
| `pg_instance` | resource attributes (`db.system`, `db.name`, `pgsleuth.replica.id`) |
| `remediation` | attribute `pgsleuth.remediation` (JSON) |
| `otel_attributes` | merged into log record attributes |

The agent has *one* serialization step. No two-representation drift.

### Worked example — Alarm #43 (Fsync jitter)

Manifest:

```yaml
# crates/pgsleuth-core/rules/wal_fsync_jitter.yaml
id: storage.wal.fsync.jitter
version: 1
tier: 3
min_pg_version: 13
requires:
  - ebpf.block_rq
evaluator: fsync_jitter_v1
params:
  commit_latency_ms_threshold: 10
window:
  kind: custom        # the evaluator owns rolling histogram state
severity: high
summary: "WAL device commit latency > {threshold_ms}ms for {breach_intervals} intervals"
remediation:
  text: "Investigate WAL device contention; check device IO queue depth"
  knobs:
    - "wal_sync_method"
    - "synchronous_commit"
```

Evaluator (sketch, lives in `pgsleuth-core/src/evaluators/fsync_jitter.rs`):

```rust
pub struct FsyncJitterV1 {
    threshold_ms: u64,
    histograms: HashMap<DeviceId, RollingHistogram>,
    breach_streak: HashMap<DeviceId, u32>,
}

impl Evaluator for FsyncJitterV1 {
    fn on_sample(&mut self, sample: &Sample) -> Option<Finding> { /* ... */ }
}
```

What this shows:

- The YAML expresses what's *catalog* (id, severity, prose, knobs) and
  what's *configurable* (threshold).
- The evaluator owns the stateful bit.
- `requires: ebpf.block_rq` means on a Tier-1 install the rule is silently
  excluded — *without* hardcoding tier-3-ness in the engine.

## Layout

```
crates/pgsleuth-core/
├── src/
│   ├── lib.rs              # re-exports
│   ├── finding.rs          # Finding, Severity, Tier, Remediation, ...
│   ├── manifest.rs         # YAML schema (serde) + load + validate
│   ├── engine.rs           # rule loader, capability filter, sample broker
│   ├── window.rs           # consecutive_intervals, rolling_histogram helpers
│   └── evaluators/
│       ├── mod.rs          # registry: name → fn() -> Box<dyn Evaluator>
│       ├── threshold_v1.rs
│       ├── consecutive_intervals_v1.rs
│       ├── histogram_p95_v1.rs
│       └── fsync_jitter_v1.rs  # bespoke, lands in #43
└── rules/
    └── *.yaml
```

`pgsleuth-postgres`, `pgsleuth-otel`, `pgsleuth-cli` consume the public API
of `pgsleuth-core` and add neither traits nor new wire types — that
boundary is fixed here.

## How we'll know this is the wrong design

Concrete signals that would force a revisit:

- **More than 30% of catalog rules need bespoke evaluators.** If the YAML
  shape is too thin for the common case, collapse to pure code and accept
  the contribution cost.
- **The rule engine becomes a hot path.** If profiling on the v0.1 fixture
  shows the engine eating measurable CPU compared to collectors, revisit the
  one-task-per-rule model and consider batching.
- **`schema_version` ratchets every other rule change.** That means the
  envelope is too rigid — soften the typed fields into `serde_json::Value`
  bags before they keep dragging the brain along.
- **Capability negotiation is unreliable.** If `requires` produces false
  positives ("ebpf.block_rq available" → load fails at runtime), move
  capability discovery from startup-time to evaluator-construction-time and
  let the evaluator self-veto.

## Open questions deferred to later docs

- **002 — Rule packaging and hot reload.** Out of scope for v0.1. Will
  cover signed rule packs, partial reload, and user-authored rules.
- **003 — Cross-rule deduplication and alarm prioritization.** Defer until
  we have field experience.
- **004 — Brain-side schema compatibility policy.** What the brain does
  when it sees a `schema_version` it doesn't recognize.
