# What planning did for execution speed

> *A personal experience build log. Posted 2026-06-13.*

I just shipped Tier 1 of [pgsleuth](https://github.com/TarqWork/pgsleuth)
— a Postgres observability agent that uses eBPF for the deep signals
and OTel for everything else. 19 PRs, six catalog alarms, one focused
session. The thing I want to write down is how the planning shaped
the speed.

**Planning matters to improve speed of execution.** Concretely:

- **The alarm catalog** — [`docs/research/Database Observability Alarms.md`](https://github.com/TarqWork/pgsleuth/blob/main/docs/research/Database%20Observability%20Alarms.md)
  lists each alarm's signal, trigger, and eBPF hook before any code
  exists. Each alarm became a ~200-line PR because every meaningful
  decision was already made.

- **Design doc 001** — [`docs/design/001-rule-schema.md`](https://github.com/TarqWork/pgsleuth/blob/main/docs/design/001-rule-schema.md)
  pins the `Finding` wire format and the rule schema. The envelope
  hasn't changed shape since the first commit; every later alarm
  slotted in.

- **The `Finding` type** — [`crates/pgsleuth-core/src/finding.rs`](https://github.com/TarqWork/pgsleuth/blob/main/crates/pgsleuth-core/src/finding.rs)
  is a single Rust struct with a `schema_version` tripwire on every
  emit. The brain (still deferred) reads the same JSON from any of
  the six alarms.

- **The `ConsecutiveBreachCounter`** — [`crates/pgsleuth-core/src/window.rs`](https://github.com/TarqWork/pgsleuth/blob/main/crates/pgsleuth-core/src/window.rs)
  is the "fires after N consecutive intervals" pattern. Three alarms
  reuse it as is.

- **The OTel emitter** — [`crates/pgsleuth-otel/src/lib.rs`](https://github.com/TarqWork/pgsleuth/blob/main/crates/pgsleuth-otel/src/lib.rs)
  and [`metrics.rs`](https://github.com/TarqWork/pgsleuth/blob/main/crates/pgsleuth-otel/src/metrics.rs)
  ship log records for Findings and histograms for WAL-IO latency.
  Every alarm hooks the same emitter.

- **A delivery-worker prompt with guardrails** drove the work —
  read-only DB role, no generated files in commits, branch per task,
  verification inside Docker before any PR. Claude Code's `/loop`
  iterated through the worklist: pick the next eligible task,
  implement, verify, open the PR, mark the worklist. I merged
  between iterations.

## Three things that were new to me (and aren't anymore)

**1. The kernel encodes `dev_t` differently from glibc.** I had not
seen this before. The Postgres extension's `pgsleuth_wal_device()`
was reporting `254:1` — glibc's `makedev` on the overlay's `st_dev`.
The kernel's `block:block_rq_issue` tracepoint reported `254:0`.
The encodings don't agree: the kernel uses `(major << 20) | minor`,
glibc uses a 32-bit-friendly split. The parser that bridges them
lives in [`parse_kernel_dev_t`](https://github.com/TarqWork/pgsleuth/blob/main/crates/pgsleuth-ebpf-loader/src/main.rs).

**2. `pg_authid` is superuser-only.** The first version of the
`pg_stat_statements` collector joined to it for `rolname`. The
unprivileged `pgsleuth_agent` role couldn't run the query. Switched
to `pg_roles` (public view) in [`crates/pgsleuth-postgres/src/stat_statements.rs`](https://github.com/TarqWork/pgsleuth/blob/main/crates/pgsleuth-postgres/src/stat_statements.rs).
The architectural invariant "the agent is read-only" is now enforced
at the role level on the fixture itself.

**3. Tracefs has to be mounted *inside* the container.** Bind-mounting
`/sys/kernel/tracing` from the host exposes an empty directory.
aya's tracepoint attach fails with `"tracefs not found"`. The fix is
`mount -t tracefs tracefs /sys/kernel/tracing` at container boot —
in [`infra/docker/setup-postgres.sh`](https://github.com/TarqWork/pgsleuth/blob/main/infra/docker/setup-postgres.sh).
`CAP_SYS_ADMIN` was already there for bpffs.

## What I'm taking away

Sharper plans land code faster. The catalog, the design doc, and the
delivery prompt did most of the work that looks like "speed" from the
outside. The loop just kept executing the plan honestly — verify in
Docker, no shortcuts, one issue per PR — and the foundation work paid
itself back on every subsequent alarm.

Humans plan rigorously. The loop executes ruthlessly.

The repo is at [github.com/TarqWork/pgsleuth](https://github.com/TarqWork/pgsleuth).
The catalog and the design doc are both in there if you want to see
the shape of the planning that drove the execution.
