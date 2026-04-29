# pgsleuth — Tasks

This file is the source of truth for the GitHub Project. The bootstrap script (`scripts/bootstrap-github.sh`) parses it and creates one issue per task.

**Format:** Each task is a `### TASK:` heading followed by a body. Labels go on a `Labels:` line. The script handles the rest.

---

### TASK: Decide and register the domain

**Labels:** week-0, infrastructure, long-term

Candidates: `pgsleuth.dev`, `pgsleuth.io`, `pgsleuth.sh`. Verify availability, register one. Update README to remove `TODO(domain)`. Set up DNS pointing to a future blog/docs site (no rush on the site itself).

---

### TASK: Set up minimal blog/docs site infrastructure

**Labels:** week-0, infrastructure

Pick: Astro or Hugo. Dark theme, content-over-design. Stand up under the registered domain, but **do not publish anything yet** — no posts go live until v0.2 launch (week 10). The site exists; it's empty.

---

### TASK: Identify the 5 target DBAs/SREs to talk to

**Labels:** week-0, validation

List 5 names. People who run Postgres in production, willing to spend 30 minutes giving feedback on early design and observability pain. Mix: at least 2 self-managed, at least 2 managed (RDS/Aurora/Cloud SQL), at least 1 K8s-Postgres operator.

---

### TASK: Schedule the 5 DBA conversations for week 2

**Labels:** week-0, validation

Calendar invites out by end of week 1.

---

### TASK: Spike — eBPF feasibility (2 days)

**Labels:** week-1, spike, technical

Fill in `docs/research/ebpf-feasibility.md`. Goal: green/yellow/red verdict on `aya` for our use case. See the placeholder file for the structured questions.

---

### TASK: Spike — Managed Postgres data audit (1 day)

**Labels:** week-1, spike, technical

Fill in `docs/research/managed-pg-data.md`. Stand up RDS PG17 free tier, Cloud SQL trial. Document what's actually accessible.

---

### TASK: Read pganalyze blog archive — postgres-internals tag

**Labels:** week-1, research

~4 hours. Skim posts tagged `postgres-internals`. Note insights worth referencing later. The goal is calibration on what's been written about — not to replicate it.

---

### TASK: Read OpenTelemetry DB semantic conventions spec

**Labels:** week-1, research

End to end. ~2 hours. We're emitting OTel-native; we should know the spec by heart before week 3 when the emitter starts.

---

### TASK: Skim Postgres source — pg_stat_* implementation

**Labels:** week-1, research

`src/backend/utils/adt/pgstatfuncs.c`. ~2 hours. Goal: understand what's actually computed (not just what the docs say) for the views we depend on most.

---

### TASK: Verify make dev / test / lint / ci work end-to-end

**Labels:** week-1, infrastructure

On a fresh clone: `make dev && make test && make lint && make ci` — all green. Document anything that broke. The two-stack split rule says this must work from day 1.

---

### TASK: Push the repo public to tarqwork/pgsleuth

**Labels:** week-1, infrastructure

After CI is green. README states pre-alpha, no support, no advertising until v0.2.

---

### TASK: Open a "design feedback wanted" issue against 000-architecture

**Labels:** week-1, design, validation

Pin it. Use it as the single anchor when soliciting feedback from the 5 DBAs.

---

### TASK: First weeknotes post

**Labels:** week-1, content

End of week 1, in `blogs/2026-W18-weeknotes.md` or similar. ~300 words is fine. Discipline > polish. The first one is the hardest.

---

## Long-term (post-week-1)

### TASK: Design doc 001 — Rule schema and rule engine

**Labels:** long-term, design, phase-1

Before week 3 starts. Resolves: rule data model, version-gating, tier-gating, how the engine evaluates rules, how findings are emitted. This is load-bearing for the v0.1 deliverable.

---

### TASK: Design doc 002 — Plan normalization format

**Labels:** long-term, design, phase-2

Before week 7 starts. The format the agent normalizes `EXPLAIN (ANALYZE)` output into for the brain to consume.

---

### TASK: Design doc 003 — Workload fingerprinting algorithm

**Labels:** long-term, design, phase-3

Before week 11 starts. The technically hardest piece of v1.0. Worth a dedicated doc with alternatives.

---

### TASK: Design doc 004 — Hosted Cloud-Enhanced tier architecture

**Labels:** long-term, design, commercial

Before week 11 — the 4-week commercial sprint at week 12 needs this resolved. Multi-tenant, BYO-LLM-key, billing.

---

### TASK: CLA decision

**Labels:** long-term, governance

Before v0.2 (week 10). Decide whether to require contributor license assignment for relicensing flexibility. If yes, set up via cla-assistant.io or similar.

---

### TASK: v0.2 launch checklist

**Labels:** long-term, launch, phase-2

By end of phase 2. Includes: HN post draft, Postgres Weekly outreach, Planet PostgreSQL RSS, demo video (90s), landing page copy, the 5 blog posts that ship with launch.

---

### TASK: Conference CFP submissions

**Labels:** long-term, content

Submit *before* the project is done — deadlines force shipping. PostgresConf, SREcon, KubeCon, PGDay events.

---

### TASK: Bring up local Postgres test fixture

**Labels:** long-term, infrastructure

A `docker-compose.yml` or similar that spins up a primary + 2 replicas with `pg_stat_statements` and `auto_explain` enabled. Used by every developer (currently: 1) and by CI integration tests when those land.
