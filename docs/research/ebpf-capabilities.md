# eBPF capability matrix (Tier-1 v0)

| | |
|---|---|
| Status | v0 — written for #40 |
| Last revised | 2026-06-13 |

What each eBPF program in pgsleuth uses, which kernel capability it
needs, and which environments can actually grant it.

## Capabilities at a glance

| Capability | Purpose in pgsleuth | Required by |
|---|---|---|
| `CAP_BPF` | Load eBPF programs, create/update BPF maps. Split out of `CAP_SYS_ADMIN` in kernel 5.8 (2020). | All probes |
| `CAP_PERFMON` | `perf_event_open(2)`. Needed to attach kprobes and tracepoints. Also split out of `CAP_SYS_ADMIN` in 5.8. | All probes |
| `CAP_SYS_ADMIN` | Mount `tracefs` at `/sys/kernel/tracing` from inside a container; certain bpffs ops. | The tracefs mount in `setup-postgres.sh` |
| `CAP_NET_ADMIN` | Attach network-tier eBPF programs (`sched:sched_switch`, `inet_csk_accept`, `sock:inet_sock_set_state`). | **Future** — eBPF half of #44, NOT shipped in v0 |

Effective v0 set: `BPF + PERFMON + SYS_ADMIN`. `NET_ADMIN` comes back
when the connection-storm eBPF probes land in the rule engine.

## Per-environment availability

| Environment | `BPF` + `PERFMON` | `SYS_ADMIN` | `NET_ADMIN` | Tier 3 verdict |
|---|---|---|---|---|
| Self-managed Docker / VM, kernel ≥ 5.8 | grantable | grantable | grantable | full Tier 3 |
| Self-managed K8s, PSA `baseline` | grantable via SCC patch | grantable | grantable | full Tier 3 |
| Self-managed K8s, PSA `restricted` | rejected | rejected | rejected | Tier 1 only |
| Managed K8s — GKE Autopilot / EKS Fargate / AKS Virtual Nodes | rejected | rejected | rejected | Tier 1 only |
| Managed Postgres — RDS / Aurora / Cloud SQL | n/a (no host access) | n/a | n/a | Tier 1 + Tier 2 cloud APIs |

See [`k8s-ebpf-caveats.md`](k8s-ebpf-caveats.md) for the operator-by-operator
story (CNPG / Spilo / Crunchy PGO).

## Why `CAP_NET_ADMIN` is intentionally absent in v0

The compose file in `infra/docker/docker-compose.yml` shipped `NET_ADMIN`
through #18, #43, and #45 because we were following the
`pgsleuth-ebpf-poc` cap list. None of the kernel probes we actually
ship today touch the network subsystem — they're all block-layer
(`block:block_rq_*`), syscall (`syscalls:sys_enter_openat`/`unlinkat`),
or file-system (`vfs_open` kprobe). Dropping `NET_ADMIN` matches the
"minimum that works" requirement from #40.

The cap goes back when the rule engine wires:
- `sched:sched_switch` / `sched:sched_process_fork` (#44 eBPF half) —
  fork-rate and context-switch churn correlated with the polling
  backend count.
- `inet_csk_accept` (#44 eBPF half) — TCP accept events on the Postgres
  port to confirm the count we polled from `pg_stat_activity` matches
  what the kernel saw.
- `sock:inet_sock_set_state` (alternative path to `inet_csk_accept`) —
  if Postgres is using `tcp_keepalive` or other socket options the
  former misses.

When that work lands, this doc gets an entry adding `NET_ADMIN` back
under the v0.1 column.

## Verifying after the tighten

The eBPF feasibility compose flow boots, attaches every probe we
currently ship, and reports `Successfully attached tracepoint ...`
for all four (`block_rq_issue`, `block_rq_complete`,
`sys_enter_openat`, `sys_enter_unlinkat`) plus the `vfs_open` kprobe.
A subsequent forced spill via low `work_mem` produces the temp-file
spill Finding from #45; a forced write via `dd ... oflag=direct`
produces the block-layer events from #18. Both run without
`CAP_NET_ADMIN` granted.

## Open follow-ups

- **Per-cap runtime probe in pgsleuth-cli.** Future:
  `pgsleuth probe-caps` that reports which kernel capabilities the
  current process holds and which alarms each capability enables.
- **Graceful tier downgrade.** Today the loader fails loudly if a
  tracepoint can't attach. v0.1 should downgrade to Tier-1-only and
  log an explicit "Tier 3 alarm X disabled: missing CAP_<NAME>".
