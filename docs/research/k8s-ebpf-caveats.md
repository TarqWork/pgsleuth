# Postgres-on-Kubernetes eBPF caveats

| | |
|---|---|
| Status | v0 — written for #42, consumed by #48 |
| Last revised | 2026-06-13 |

eBPF programs need `CAP_BPF` (or the older `CAP_SYS_ADMIN`) plus
`CAP_PERFMON` to attach kprobes/tracepoints, and a writable `bpffs` or
`tracefs` mount inside the pod. Major Postgres Kubernetes operators
each have a different story about which of those are reachable. This
doc is the matrix; **Alarm 14 (cgroup CPU throttling)** in particular
needs `CAP_BPF` + `CAP_PERFMON` to attach `kprobe:throttle_cfs_rq`.

The Tier-3 (deep / eBPF) tier ships **only** where the operator can
grant the capabilities below. Tier 1 polling rules still work
everywhere; Tier 2 cloud-API rules only need the cloud provider's
permissions.

---

## CloudNativePG (CNPG) — Operator from EDB

- **Pod security default:** runs as non-root (`runAsNonRoot: true`),
  `allowPrivilegeEscalation: false`, no capabilities by default. Per
  the [security context docs][cnpg-sec], the operator enforces a
  baseline restricted SecurityContext on every PG pod.
- **Adding capabilities:** the `Cluster` CRD exposes
  `.spec.containers[].securityContext` overrides, but the operator
  validates the diff — adding `CAP_BPF` / `CAP_PERFMON` is allowed,
  adding `CAP_SYS_ADMIN` is rejected on modern releases (≥ 1.22).
- **bpffs / tracefs:** `hostPath` volumes work but require cluster
  admin to set `policy/restricted` exceptions on the namespace. Most
  managed Kubernetes (GKE Autopilot, EKS Fargate) disallow `hostPath`
  entirely → tracefs simply not reachable.
- **Tier-3 caveat:** "Available on self-managed CNPG; explicit
  capability + hostPath grant required. Unavailable on Autopilot /
  Fargate / any cluster denying hostPath."

[cnpg-sec]: https://cloudnative-pg.io/documentation/current/security/

## Zalando postgres-operator (Spilo)

- **Pod security default:** Spilo runs as `postgres` (UID 101).
  The operator's default container exposes
  `securityContext.privileged: false` and no additional caps. The
  [docs on additional containers][spilo-pods] note that arbitrary
  sidecar capabilities can be set via the `additional_secret_mount`
  / `pod_priority_class_name` knobs.
- **Adding capabilities:** the `OperatorConfiguration` CRD has
  `pod_security_context.run_as_non_root`; CAP_BPF can be added via
  the per-cluster `podPriorityClassName` + a sidecar pattern.
  Restricted-PSA namespaces refuse the diff.
- **bpffs / tracefs:** Spilo's `volumes:` field is overridable —
  attach a `hostPath` mount the same way the operator's PgBouncer
  sidecar pattern works.
- **Tier-3 caveat:** "Available on permissive Spilo deployments via
  sidecar capability grant; not available under
  Pod-Security-Standards `restricted` mode."

[spilo-pods]: https://postgres-operator.readthedocs.io/en/latest/administrator/#sidecars-for-postgres-clusters

## Crunchy Data Postgres Operator (PGO)

- **Pod security default:** PGO 5.x ships with the OpenShift
  `restricted-v2` SCC in mind; pods run as non-root with no extra
  caps. The Crunchy docs explicitly call out that
  `securityContext.capabilities.add` is honored on Kubernetes but
  blocked on OpenShift Container Platform unless cluster-admin
  grants the SCC.
- **Adding capabilities:** straightforward Kubernetes CRD patch
  (`.spec.instances[].containers[].securityContext.capabilities.add`).
  On OpenShift, requires an SCC change — usually a no-go in regulated
  environments.
- **bpffs / tracefs:** PGO's `dataVolumeClaimSpec` is the only volume
  it manages; injecting a sidecar with a `hostPath` is doable on
  vanilla K8s. OpenShift blocks `hostPath` under any SCC short of
  `privileged`.
- **Tier-3 caveat:** "Available on plain Kubernetes with the capability
  patch; rarely available on OpenShift without a privileged SCC.
  Tier-3 prerequisites should be checked at agent startup and the
  Tier downgraded gracefully if missing."

## Summary matrix

| Operator   | `CAP_BPF` / `CAP_PERFMON` grantable | `hostPath` for tracefs | Default Tier-3 availability |
|------------|-------------------------------------|------------------------|------------------------------|
| CNPG       | yes via Cluster CRD (≥ 1.22)       | yes if PSA allows      | self-managed only            |
| Spilo      | yes via sidecar pattern             | yes via volumes patch  | permissive mode only         |
| Crunchy PGO | yes on plain K8s; no on OCP        | yes on plain K8s; no on OCP | plain K8s only           |

## Common gotchas across all three

1. **Pod Security Standards `restricted`** automatically rejects
   `CAP_BPF` and `hostPath`. Every modern cluster has this baseline.
   The pgsleuth agent must surface a clear *"Tier 3 unavailable,
   running Tier 1 only"* startup line, not a cryptic syscall failure.
2. **GKE Autopilot, EKS Fargate, AKS Virtual Nodes** disallow
   `hostPath` and arbitrary capabilities at the platform level —
   independent of the operator. Tier 3 is simply unavailable on these.
3. **Cgroup ID stability across pod restarts.** A K8s pod's cgroup ID
   changes on every restart. Alarm 14 must re-derive the cgroup ID
   from `/proc/<postmaster_pid>/cgroup` at startup, not cache it
   across container lifetimes.
4. **Network namespace isolation.** Pod-network kprobes
   (`inet_csk_accept`) need the host network namespace to see all
   client connections. Operators that put PG in `hostNetwork: true`
   (rare) work; everything else only sees the pod's own NS.

## What this changes downstream

- **Alarm 14 (#48):** the cgroup-id filter is the right primary
  mechanism. The implementation reads
  `/proc/<postmaster_pid>/cgroup` at startup; if the cgroup ID is 0
  or the file is unreadable (PSA refusal), the alarm refuses to
  attach and the agent logs "Tier 3 alarm 14 unavailable in this pod
  context". No fake-success.
- **Tier capability negotiation (#22's `requires:` list):** the
  capability set `ebpf.cgroup_throttle` is the gate. Reading this
  doc tells the operator why their environment may not have it.

## Open questions for follow-up

- Concrete capability test in pgsleuth-cli (`pgsleuth probe-tier3`)
  that returns a structured "ready / missing capability X / missing
  tracefs / missing hostPath" so operators can self-diagnose without
  digging into the failure mode. Not v0; tracked as future work.
- A small per-operator "how to grant the capability" snippet
  collection in the agent docs once #48 ships and we know which
  operator-side tickets users actually file.
