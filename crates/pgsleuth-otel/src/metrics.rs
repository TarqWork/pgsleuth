// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! OTLP metrics pipeline for pgsleuth.
//!
//! Sibling to the log [`Emitter`](crate::Emitter) in `lib.rs`; the two
//! share an OTLP endpoint but live on separate `OTel` providers
//! because log records and metrics ride different SDK pipelines in
//! 0.24. The first metric this crate ships is
//! `pgsleuth.wal.io.latency`, the histogram driving the v0 fsync-jitter
//! alarm (#43).

use std::time::Duration;

use anyhow::{Context, Result};
use opentelemetry::{
    metrics::{Histogram, Meter, MeterProvider as _},
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{metrics::SdkMeterProvider, runtime};

use opentelemetry::metrics::Counter;

use crate::EmitterConfig;

/// Instrumentation scope name reported on every metric record.
pub const METRICS_SCOPE: &str = "pgsleuth";

/// One delta to record on `pgsleuth.pg.stmt.*` counters. Constructed
/// by the cli collector from a pair of `StatementSample`s.
pub struct PgStmtDelta<'a> {
    /// `pg_stat_statements.queryid`.
    pub queryid: i64,
    /// `pg_database.datname`.
    pub database: &'a str,
    /// `pg_authid.rolname`.
    pub username: &'a str,
    /// Increment for `pgsleuth.pg.stmt.calls`.
    pub calls: u64,
    /// Increment for `pgsleuth.pg.stmt.total_exec_time_ms`.
    pub exec_time_ms: u64,
    /// Increment for `pgsleuth.pg.stmt.rows`.
    pub rows: u64,
    /// Increment for `pgsleuth.pg.stmt.shared_blks_hit`.
    pub blks_hit: u64,
    /// Increment for `pgsleuth.pg.stmt.shared_blks_read`.
    pub blks_read: u64,
}

/// Sibling of [`crate::Emitter`] for metrics. Owns an `SdkMeterProvider`
/// + the named histograms pgsleuth records into.
pub struct MetricsEmitter {
    provider: SdkMeterProvider,
    wal_io_latency: Histogram<u64>,
    // pg_stat_statements counters — collector adds the *delta* since
    // the previous poll on each call so the wire counter stays
    // monotonically increasing.
    pg_stmt_calls: Counter<u64>,
    pg_stmt_exec_time_ms: Counter<u64>,
    pg_stmt_rows: Counter<u64>,
    pg_stmt_blks_hit: Counter<u64>,
    pg_stmt_blks_read: Counter<u64>,
}

impl MetricsEmitter {
    /// Build the `OTLP` metrics exporter, install a periodic reader on
    /// the current tokio runtime (1-second export interval), and
    /// pre-build the `pgsleuth.wal.io.latency` histogram.
    ///
    /// Must be called from inside a tokio runtime — the periodic reader
    /// spawns onto it.
    ///
    /// # Errors
    ///
    /// Returns an error if the `OTLP` exporter or pipeline cannot be
    /// built (typically a malformed endpoint).
    pub fn try_new(config: &EmitterConfig) -> Result<Self> {
        let provider = opentelemetry_otlp::new_pipeline()
            .metrics(runtime::Tokio)
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(&config.otlp_endpoint),
            )
            .with_period(Duration::from_secs(1))
            .with_timeout(Duration::from_secs(3))
            .build()
            .context("failed to install `OTLP` metrics pipeline")?;

        let meter: Meter = provider.meter(METRICS_SCOPE);
        let wal_io_latency = meter
            .u64_histogram("pgsleuth.wal.io.latency")
            .with_description(
                "Per-IO latency on the WAL device, in nanoseconds. \
                 Attributes: device (kernel dev_t), op (read|write|write_flush|other).",
            )
            .with_unit("ns")
            .init();

        let pg_stmt_calls = meter
            .u64_counter("pgsleuth.pg.stmt.calls")
            .with_description("pg_stat_statements.calls (delta since previous poll).")
            .init();
        let pg_stmt_exec_time_ms = meter
            .u64_counter("pgsleuth.pg.stmt.total_exec_time_ms")
            .with_description("pg_stat_statements.total_exec_time delta since previous poll.")
            .with_unit("ms")
            .init();
        let pg_stmt_rows = meter
            .u64_counter("pgsleuth.pg.stmt.rows")
            .with_description("pg_stat_statements.rows (delta since previous poll).")
            .init();
        let pg_stmt_blks_hit = meter
            .u64_counter("pgsleuth.pg.stmt.shared_blks_hit")
            .with_description("pg_stat_statements.shared_blks_hit (delta since previous poll).")
            .init();
        let pg_stmt_blks_read = meter
            .u64_counter("pgsleuth.pg.stmt.shared_blks_read")
            .with_description("pg_stat_statements.shared_blks_read (delta since previous poll).")
            .init();

        Ok(Self {
            provider,
            wal_io_latency,
            pg_stmt_calls,
            pg_stmt_exec_time_ms,
            pg_stmt_rows,
            pg_stmt_blks_hit,
            pg_stmt_blks_read,
        })
    }

    /// Record one statement-sample delta. Attributes are
    /// `pgsleuth.pg.queryid`, `db.name`, `pgsleuth.pg.user`. The cli
    /// diff-and-emit loop computes deltas — this method just adds.
    pub fn record_pg_stmt_delta(&self, delta: &PgStmtDelta<'_>) {
        let attrs = [
            KeyValue::new("pgsleuth.pg.queryid", delta.queryid.to_string()),
            KeyValue::new("db.name", delta.database.to_string()),
            KeyValue::new("pgsleuth.pg.user", delta.username.to_string()),
        ];
        self.pg_stmt_calls.add(delta.calls, &attrs);
        self.pg_stmt_exec_time_ms.add(delta.exec_time_ms, &attrs);
        self.pg_stmt_rows.add(delta.rows, &attrs);
        self.pg_stmt_blks_hit.add(delta.blks_hit, &attrs);
        self.pg_stmt_blks_read.add(delta.blks_read, &attrs);
    }

    /// Record a single per-IO latency sample on
    /// `pgsleuth.wal.io.latency`. `device` is the kernel-encoded
    /// `dev_t` as a string (the loader formats it once and reuses); `op`
    /// is the human-readable [`pgsleuth_core`]/[`pgsleuth_ebpf_common`]
    /// op class string.
    pub fn record_wal_io_latency(&self, latency_ns: u64, device: &str, op: &str) {
        self.wal_io_latency.record(
            latency_ns,
            &[
                KeyValue::new("device", device.to_string()),
                KeyValue::new("op", op.to_string()),
            ],
        );
    }

    /// Flush and tear down the meter provider. Call before the tokio
    /// runtime exits so in-flight batches are not dropped.
    pub fn shutdown(self) {
        if let Err(e) = self.provider.shutdown() {
            tracing::warn!(error = %e, "OTel meter provider shutdown reported an error");
        }
    }
}
