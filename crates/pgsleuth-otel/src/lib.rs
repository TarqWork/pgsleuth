// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! OpenTelemetry log emitter for pgsleuth findings.
//!
//! [`Emitter`] wraps an `OTLP` log pipeline and ships [`Finding`]s as
//! `OTel` log records using the mapping defined in
//! `docs/design/001-rule-schema.md` § D5. Resource attributes are
//! plumbed through verbatim from [`EmitterConfig::resource_attributes`];
//! a future per-cloud attribute layer (gated on the cloud-blueprints
//! spike, issue #12) will plug in here without changing this crate's
//! public surface.
//!
//! The mapping logic lives in [`mapping`] and is unit-tested without
//! standing up an actual exporter. [`Emitter`] itself is the thin
//! infrastructure shim.

mod mapping;
mod metrics;

pub use metrics::{MetricsEmitter, PgStmtDelta, METRICS_SCOPE};

use std::collections::BTreeMap;
use std::time::SystemTime;

use anyhow::{Context, Result};
use std::borrow::Cow;

use opentelemetry::{
    logs::{AnyValue, LogRecord, Logger, LoggerProvider as _},
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{logs::LoggerProvider, runtime, Resource};
use pgsleuth_core::{AttributeValue, Finding};

pub use mapping::{MappedFinding, MAPPING_VERSION};

/// Instrumentation scope name written on every emitted log record.
/// Downstream collectors can filter on this to isolate pgsleuth traffic.
pub const INSTRUMENTATION_SCOPE: &str = "pgsleuth";

/// Configuration for [`Emitter`].
///
/// `resource_attributes` are applied verbatim to the `OTLP` resource. When
/// the cloud-blueprints spike (issue #12) lands, this is the field that
/// will carry per-cloud overrides (`cloud.provider`, `cloud.region`, …);
/// today the agent passes whatever it knows and lets the operator
/// override via config.
pub struct EmitterConfig {
    /// `OTLP` gRPC endpoint, e.g. `http://localhost:4317`.
    pub otlp_endpoint: String,
    /// Value for the `OTel` `service.name` resource attribute.
    pub service_name: String,
    /// Additional `OTel` resource attributes (host, cluster, region, …).
    pub resource_attributes: BTreeMap<String, AttributeValue>,
}

/// Emits findings as `OTLP` log records.
///
/// Construct via [`Emitter::try_new`], hand findings to [`Emitter::emit`],
/// and call [`Emitter::shutdown`] before the runtime stops so the batch
/// processor flushes.
pub struct Emitter {
    provider: LoggerProvider,
}

impl Emitter {
    /// Build the `OTLP` exporter, install the batch processor on the
    /// current tokio runtime, and return a ready-to-use emitter.
    ///
    /// Must be called from inside a tokio runtime — the batch processor
    /// spawns onto it.
    ///
    /// # Errors
    ///
    /// Returns an error if the `OTLP` exporter cannot be built (typically
    /// a malformed endpoint or the runtime cannot host the batch
    /// processor).
    pub fn try_new(config: &EmitterConfig) -> Result<Self> {
        let resource = build_resource(config);

        let provider = opentelemetry_otlp::new_pipeline()
            .logging()
            .with_resource(resource)
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(&config.otlp_endpoint),
            )
            .install_batch(runtime::Tokio)
            .context("failed to install `OTLP` log pipeline")?;

        Ok(Self { provider })
    }

    /// Map `finding` to an `OTel` log record and hand it to the batch
    /// processor. Non-blocking and infallible — emit failures surface
    /// via the SDK's internal tracing, not through this call.
    pub fn emit(&self, finding: &Finding) {
        let mapped = mapping::map_finding(finding);
        let logger = self.provider.logger(INSTRUMENTATION_SCOPE);
        let mut record = logger.create_log_record();
        record.set_timestamp(mapped.timestamp);
        record.set_observed_timestamp(SystemTime::now());
        record.set_severity_number(mapped.severity_number);
        record.set_severity_text(Cow::Borrowed(mapped.severity_text));
        record.set_body(AnyValue::String(mapped.body.into()));
        for (key, value) in mapped.attributes {
            record.add_attribute(key, value);
        }
        logger.emit(record);
    }

    /// Flush and tear down the `OTLP` exporter. Call before the tokio
    /// runtime exits so in-flight batches are not dropped. Shutdown
    /// errors are reported via `tracing` and not surfaced — there is
    /// nothing the caller can do at process exit.
    pub fn shutdown(self) {
        if let Err(e) = self.provider.shutdown() {
            tracing::warn!(error = %e, "`OTel` logger provider shutdown reported an error");
        }
    }
}

fn build_resource(config: &EmitterConfig) -> Resource {
    let mut attrs = Vec::with_capacity(1 + config.resource_attributes.len());
    attrs.push(KeyValue::new("service.name", config.service_name.clone()));
    for (k, v) in &config.resource_attributes {
        attrs.push(KeyValue::new(k.clone(), attribute_to_otel(v.clone())));
    }
    Resource::new(attrs)
}

/// Convert a pgsleuth-core [`AttributeValue`] into an `OTel` [`opentelemetry::Value`].
///
/// Kept private; consumers express attributes via the pgsleuth-core type
/// so the agent boundary stays single-typed.
fn attribute_to_otel(value: AttributeValue) -> opentelemetry::Value {
    match value {
        AttributeValue::String(s) => opentelemetry::Value::String(s.into()),
        AttributeValue::Int(i) => opentelemetry::Value::I64(i),
        AttributeValue::Double(d) => opentelemetry::Value::F64(d),
        AttributeValue::Bool(b) => opentelemetry::Value::Bool(b),
    }
}
