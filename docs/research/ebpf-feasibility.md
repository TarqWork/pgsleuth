# eBPF feasibility for pgsleuth

**Status:** TODO — week 1 spike, ~2 days.

## Question being answered

Does `aya` (Rust eBPF framework) work for our use case on the Linux versions our users actually run, and what privileges does it require?

## Approach

Day 1 — Hello world:
- Install `aya` toolchain on dev machine.
- Write a minimal eBPF program that traces *one* syscall (`pread64`) on a Postgres backend process.
- Document kernel version, distro, capabilities (CAP_BPF / CAP_PERFMON / CAP_SYS_ADMIN) needed.
- Run it. Confirm output.

Day 2 — Postgres-shaped:
- Identify a Postgres backend PID via `pg_stat_activity`.
- Trace `pread64` calls from that PID specifically.
- Aggregate by file descriptor → resolve to relfilenode → table.
- Confirm the data is interesting (volume, latency).

## Inputs

- Linux kernel version on dev box: TBD
- Postgres version under test: 17.x

## Verdict

🟡 TODO — fill in after spike. Use one of:
- 🟢 Green — works, proceed with phase 5 plan as-is.
- 🟡 Yellow — works with caveats. Document caveats.
- 🔴 Red — fundamental blocker. Trigger architecture rethink.

## What this changes in the architecture

TBD — fill in based on verdict.

## Notes / scratch
