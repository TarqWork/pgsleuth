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

use crate::EmitterConfig;

/// Instrumentation scope name reported on every metric record.
pub const METRICS_SCOPE: &str = "pgsleuth";

/// Sibling of [`crate::Emitter`] for metrics. Owns an `SdkMeterProvider`
/// + the named histograms pgsleuth records into.
pub struct MetricsEmitter {
    provider: SdkMeterProvider,
    wal_io_latency: Histogram<u64>,
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

        Ok(Self {
            provider,
            wal_io_latency,
        })
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
