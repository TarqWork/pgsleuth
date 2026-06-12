# pgsleuth reference dashboards

Hand-built Grafana panels checked into the repo. These pair with the
emitted `pgsleuth.*` OTel metrics — the dashboards are *reference* shapes,
not the only way to look at the data, and you are expected to fork them
when you customize.

## `wal-io-latency.json`

Reference panel for v0 Alarm 03 (Fsync Jitter — `storage.wal.fsync.jitter`).
Renders the `pgsleuth.wal.io.latency` histogram emitted by the
`pgsleuth-ebpf-loader`:

- **Top:** P50 / P95 / P99 of write + write_flush latency.
- **Middle:** heatmap of the full latency distribution.
- **Bottom:** event rate per op class.

### Importing

1. Stand up a Prometheus-compatible OTLP receiver — easiest is the
   [OpenTelemetry Collector with the `prometheus` exporter](https://opentelemetry.io/docs/collector/configuration/),
   then point Grafana at the resulting Prometheus endpoint. Grafana
   Mimir works too.
2. Run the agent against the fixture from #10:
   ```bash
   pgsleuth-ebpf-loader \
       --bpf-object .../pgsleuth-ebpf \
       --pg-conn postgres://pgsleuth_agent:pgsleuth@localhost:5432/postgres \
       --otlp-endpoint http://localhost:4317
   ```
3. In Grafana, Dashboards → Import → upload `wal-io-latency.json`, pick the
   Prometheus datasource.

### Notes

- The Prometheus histogram name expected here is
  `pgsleuth_wal_io_latency_bucket` / `_count` / `_sum`. The OTel Collector's
  `prometheus` exporter applies that naming automatically by translating
  the OTel metric name `pgsleuth.wal.io.latency`.
- The histogram is in nanoseconds. The panel's Y-axis unit is `ns`; switch
  the unit in the panel options if you want milliseconds.
- Labels: `op` is one of `read | write | write_flush | other`. `device` is
  the kernel-encoded `dev_t` string (e.g. `dev_t=266338304`).

### Out of scope

- Wiring an OTel collector + Prometheus into `infra/docker/` — separate task.
- The Finding log record (`storage.wal.fsync.jitter`) is *not* on this
  panel; that goes to a logs explorer or to the brain.
