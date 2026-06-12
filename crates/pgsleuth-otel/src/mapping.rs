// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! [`Finding`] → `OTel` log record mapping.
//!
//! The full mapping table lives in `docs/design/001-rule-schema.md` § D5
//! and any change here must update that doc and bump
//! [`MAPPING_VERSION`].

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use opentelemetry::{
    logs::{AnyValue, Severity},
    Key,
};
use pgsleuth_core::{
    AttributeValue, Finding, PgRole, Severity as PgSeverity, Tier, FINDING_SCHEMA_VERSION,
};

/// Tripwire constant for the [`Finding`] → log record mapping shape.
/// Bump whenever a field is renamed, dropped, or its target attribute
/// changes — downstream collectors keyed on `pgsleuth.*` attributes
/// rely on this number to detect compat breaks.
pub const MAPPING_VERSION: u32 = 1;

/// Concrete shape we hand to the `OTel` SDK. Pulled out of [`super::Emitter`]
/// so the mapping logic is unit-testable without an exporter.
pub struct MappedFinding {
    /// Event time — comes from the finding's `fired_at`.
    pub timestamp: SystemTime,
    /// `OTel` severity number, mapped from [`PgSeverity`].
    pub severity_number: Severity,
    /// `OTel` severity text, matched 1:1 to `severity_number`.
    pub severity_text: &'static str,
    /// Body of the log record — the finding's summary.
    pub body: String,
    /// Flat list of attributes to attach to the log record.
    pub attributes: Vec<(Key, AnyValue)>,
}

/// Build the mapped record. See `docs/design/001-rule-schema.md` § D5.
pub fn map_finding(finding: &Finding) -> MappedFinding {
    let (severity_number, severity_text) = map_severity(finding.severity);
    let mut attributes: Vec<(Key, AnyValue)> = Vec::with_capacity(
        // 8 stable keys + evidence + remediation + per-instance + extras.
        12 + finding.otel_attributes.len(),
    );

    attributes.push((
        Key::new("pgsleuth.schema.version"),
        AnyValue::Int(i64::from(finding.schema_version)),
    ));
    attributes.push((
        Key::new("pgsleuth.mapping.version"),
        AnyValue::Int(i64::from(MAPPING_VERSION)),
    ));
    attributes.push((
        Key::new("pgsleuth.finding.schema.version"),
        AnyValue::Int(i64::from(FINDING_SCHEMA_VERSION)),
    ));
    attributes.push((
        Key::new("pgsleuth.rule.id"),
        AnyValue::String(finding.rule_id.clone().into()),
    ));
    attributes.push((
        Key::new("pgsleuth.rule.version"),
        AnyValue::Int(i64::from(finding.rule_version)),
    ));
    attributes.push((
        Key::new("pgsleuth.tier"),
        AnyValue::String(tier_str(finding.tier).into()),
    ));
    attributes.push((
        Key::new("pgsleuth.pg.instance"),
        AnyValue::String(finding.pg_instance.id.clone().into()),
    ));
    attributes.push((
        Key::new("pgsleuth.pg.role"),
        AnyValue::String(role_str(finding.pg_instance.role).into()),
    ));
    if let Some(db_name) = &finding.pg_instance.db_name {
        // Maps to the `OTel` database semantic convention attribute.
        attributes.push((
            Key::new("db.name"),
            AnyValue::String(db_name.clone().into()),
        ));
    }
    // Evidence: serialized JSON. We do not split into per-key attributes
    // because the shape is rule-specific and we want it round-trippable.
    if !finding.evidence.is_null() {
        attributes.push((
            Key::new("pgsleuth.evidence"),
            AnyValue::String(finding.evidence.to_string().into()),
        ));
    }
    if let Ok(remediation_json) = serde_json::to_string(&finding.remediation) {
        attributes.push((
            Key::new("pgsleuth.remediation"),
            AnyValue::String(remediation_json.into()),
        ));
    }
    for (k, v) in &finding.otel_attributes {
        attributes.push((Key::new(k.clone()), attribute_to_any(v.clone())));
    }

    MappedFinding {
        timestamp: chrono_to_system_time(finding.fired_at),
        severity_number,
        severity_text,
        body: finding.summary.clone(),
        attributes,
    }
}

/// Convert a UTC chrono timestamp into a `SystemTime`.
///
/// `chrono::DateTime<Utc>` does not implement `Into<SystemTime>` directly
/// in the version we pin, so we build one from the Unix seconds + subsec
/// nanos. Pre-1970 timestamps fall back to `UNIX_EPOCH` — pgsleuth
/// findings will never carry one.
fn chrono_to_system_time(dt: DateTime<Utc>) -> SystemTime {
    let secs = dt.timestamp();
    let nanos = dt.timestamp_subsec_nanos();
    if let Ok(secs_u64) = u64::try_from(secs) {
        UNIX_EPOCH + Duration::new(secs_u64, nanos)
    } else {
        UNIX_EPOCH
    }
}

/// Map pgsleuth-core severity → `OTel` severity (number + text).
///
/// `OTel`'s `SeverityNumber` table reserves bands per severity word
/// (1-4 TRACE, 5-8 DEBUG, 9-12 INFO, 13-16 WARN, 17-20 ERROR,
/// 21-24 FATAL); we pick the middle of each relevant band.
fn map_severity(severity: PgSeverity) -> (Severity, &'static str) {
    match severity {
        PgSeverity::Info => (Severity::Info, "INFO"),
        PgSeverity::Low => (Severity::Info4, "INFO4"),
        PgSeverity::Medium => (Severity::Warn, "WARN"),
        PgSeverity::High => (Severity::Error, "ERROR"),
        PgSeverity::Critical => (Severity::Fatal, "FATAL"),
    }
}

fn tier_str(tier: Tier) -> &'static str {
    match tier {
        Tier::Standard => "standard",
        Tier::CloudEnhanced => "cloud_enhanced",
        Tier::Deep => "deep",
    }
}

fn role_str(role: PgRole) -> &'static str {
    match role {
        PgRole::Primary => "primary",
        PgRole::Replica => "replica",
        PgRole::Unknown => "unknown",
    }
}

fn attribute_to_any(value: AttributeValue) -> AnyValue {
    match value {
        AttributeValue::String(s) => AnyValue::String(s.into()),
        AttributeValue::Int(i) => AnyValue::Int(i),
        AttributeValue::Double(d) => AnyValue::Double(d),
        AttributeValue::Bool(b) => AnyValue::Boolean(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use pgsleuth_core::{PgInstanceRef, Remediation};
    use std::collections::BTreeMap;

    fn finding() -> Finding {
        let mut otel_attributes = BTreeMap::new();
        otel_attributes.insert(
            "pgsleuth.replica.id".to_string(),
            AttributeValue::String("replica-2".to_string()),
        );
        Finding {
            schema_version: FINDING_SCHEMA_VERSION,
            rule_id: "replica.lag.high".to_string(),
            rule_version: 1,
            tier: Tier::Standard,
            severity: PgSeverity::High,
            fired_at: chrono::Utc.with_ymd_and_hms(2026, 6, 12, 15, 0, 0).unwrap(),
            pg_instance: PgInstanceRef {
                id: "prod-main".to_string(),
                db_name: Some("app".to_string()),
                role: PgRole::Replica,
            },
            summary: "Replica prod-main lag 142s exceeds 60s".to_string(),
            evidence: serde_json::json!({ "lag_seconds": 142, "threshold_seconds": 60 }),
            remediation: Remediation {
                text: "Investigate write volume on primary".to_string(),
                knobs: vec!["max_wal_senders".to_string()],
            },
            otel_attributes,
        }
    }

    fn attr<'a>(mapped: &'a MappedFinding, key: &str) -> &'a AnyValue {
        &mapped
            .attributes
            .iter()
            .find(|(k, _)| k.as_str() == key)
            .unwrap_or_else(|| panic!("attribute {key} missing from mapping"))
            .1
    }

    #[test]
    fn maps_body_and_severity() {
        let m = map_finding(&finding());
        assert_eq!(m.body, "Replica prod-main lag 142s exceeds 60s");
        assert!(matches!(m.severity_number, Severity::Error));
        assert_eq!(m.severity_text, "ERROR");
    }

    #[test]
    fn maps_rule_identity_attributes() {
        let m = map_finding(&finding());
        assert!(matches!(
            attr(&m, "pgsleuth.rule.id"),
            AnyValue::String(s) if s.as_str() == "replica.lag.high"
        ));
        assert!(matches!(
            attr(&m, "pgsleuth.rule.version"),
            AnyValue::Int(1)
        ));
        assert!(matches!(
            attr(&m, "pgsleuth.tier"),
            AnyValue::String(s) if s.as_str() == "standard"
        ));
    }

    #[test]
    fn db_name_uses_otel_semconv_key() {
        let m = map_finding(&finding());
        assert!(matches!(
            attr(&m, "db.name"),
            AnyValue::String(s) if s.as_str() == "app"
        ));
    }

    #[test]
    fn missing_db_name_is_dropped() {
        let mut f = finding();
        f.pg_instance.db_name = None;
        let m = map_finding(&f);
        assert!(m.attributes.iter().all(|(k, _)| k.as_str() != "db.name"));
    }

    #[test]
    fn null_evidence_is_dropped() {
        let mut f = finding();
        f.evidence = serde_json::Value::Null;
        let m = map_finding(&f);
        assert!(m
            .attributes
            .iter()
            .all(|(k, _)| k.as_str() != "pgsleuth.evidence"));
    }

    #[test]
    fn version_tripwires_are_emitted() {
        let m = map_finding(&finding());
        assert!(matches!(
            attr(&m, "pgsleuth.mapping.version"),
            AnyValue::Int(v) if i64::from(MAPPING_VERSION) == *v
        ));
        assert!(matches!(
            attr(&m, "pgsleuth.finding.schema.version"),
            AnyValue::Int(v) if i64::from(FINDING_SCHEMA_VERSION) == *v
        ));
    }

    #[test]
    fn custom_otel_attributes_passed_through() {
        let m = map_finding(&finding());
        assert!(matches!(
            attr(&m, "pgsleuth.replica.id"),
            AnyValue::String(s) if s.as_str() == "replica-2"
        ));
    }

    #[test]
    fn all_severity_levels_map() {
        for sev in [
            PgSeverity::Info,
            PgSeverity::Low,
            PgSeverity::Medium,
            PgSeverity::High,
            PgSeverity::Critical,
        ] {
            let mut f = finding();
            f.severity = sev;
            // Should not panic and should produce a non-empty severity text.
            let m = map_finding(&f);
            assert!(!m.severity_text.is_empty());
        }
    }
}
