// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! [`Finding`] and its supporting types.
//!
//! See `docs/design/001-rule-schema.md` § D5 for the source of truth on
//! every field below — keep this file in sync with that doc.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Envelope schema version for [`Finding`]. Bump on a *breaking* change to
/// the envelope (field rename, type change, required-field addition). The
/// brain pins acceptable versions and may refuse or down-convert.
///
/// Independent of any individual rule's `rule_version` — see [`Finding`].
pub const FINDING_SCHEMA_VERSION: u32 = 1;

/// Which collection tier produced this finding.
///
/// See the [tier model in design 000](../../../docs/design/000-architecture.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Postgres views only. Works everywhere including managed.
    Standard,
    /// Cloud provider APIs (`CloudWatch`, Cloud Logging). Managed only.
    CloudEnhanced,
    /// eBPF and on-host signals. Self-managed only.
    Deep,
}

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational; no action expected.
    Info,
    /// Low priority; review eventually.
    Low,
    /// Worth attention this on-call rotation.
    Medium,
    /// Investigate now.
    High,
    /// Page someone.
    Critical,
}

/// Cluster role of a Postgres instance — primary or a replica.
///
/// Many rules behave differently on the primary vs a replica; this is
/// surfaced as a typed field on the finding rather than buried in evidence
/// so the brain and downstream consumers can filter without parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PgRole {
    /// The primary / read-write instance.
    Primary,
    /// A read replica (streaming or logical).
    Replica,
    /// Role unknown at emit time (rare; logged as a soft anomaly).
    Unknown,
}

/// Identifier for the Postgres instance a finding is about.
///
/// `id` is the operator-meaningful name the agent was configured with
/// (cluster name, hostname, RDS identifier — whatever the user set).
/// `db_name` is the logical database the rule queried, when applicable;
/// rules that operate at cluster scope leave it `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PgInstanceRef {
    /// Operator-meaningful cluster/instance identifier.
    pub id: String,
    /// Optional logical database name (`db.name` in `OTel` semantic conventions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_name: Option<String>,
    /// Cluster role.
    pub role: PgRole,
}

/// Structured remediation suggestion attached to a finding.
///
/// `text` is the prose the brain may show or rewrite. `knobs` lists the
/// concrete Postgres or system configuration parameters an operator might
/// touch — kept as flat strings so downstream tooling can grep without
/// knowing pgsleuth's catalog format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remediation {
    /// Human-readable suggestion.
    pub text: String,
    /// Specific config knobs an operator could adjust (e.g.
    /// `"wal_sync_method"`). Empty when remediation is purely investigative.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub knobs: Vec<String>,
}

/// A typed value suitable for an `OTel` log-record attribute.
///
/// We deliberately do not lean on `serde_json::Value` here because `OTel`
/// attribute values are typed (string, int, double, bool, array, kvlist)
/// and we want the wire shape unambiguous at the agent boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum AttributeValue {
    /// `UTF-8` string attribute.
    String(String),
    /// Signed 64-bit integer attribute.
    Int(i64),
    /// 64-bit floating point attribute.
    Double(f64),
    /// Boolean attribute.
    Bool(bool),
}

/// A diagnostic finding emitted by a rule.
///
/// The brain consumes findings as JSON. Findings are the only interface
/// between the agent (Rust) and the brain (Python). Each finding maps 1:1
/// to one `OTel` log record — see design doc 001 § D5 for the field mapping.
///
/// `schema_version` and `rule_version` are distinct on purpose:
/// `schema_version` tracks the envelope; `rule_version` tracks the
/// individual rule's thresholds/semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Envelope schema version — defaults to [`FINDING_SCHEMA_VERSION`].
    pub schema_version: u32,

    /// Stable rule identifier (e.g. `"replica.lag.high"`).
    pub rule_id: String,
    /// Monotonic rule version. Bump when this rule's thresholds or
    /// semantics change.
    pub rule_version: u32,

    /// Which tier of collector data the rule used.
    pub tier: Tier,
    /// How urgent this finding is.
    pub severity: Severity,

    /// When the rule decided to fire. UTC, `RFC 3339` on the wire.
    pub fired_at: DateTime<Utc>,

    /// Which Postgres instance this finding is about.
    pub pg_instance: PgInstanceRef,

    /// Human-readable, *interpolated* summary. The brain may rewrite it.
    pub summary: String,

    /// Structured evidence the rule used to decide. The brain reasons
    /// over this; `OTel` exporters drop it into the log record's body or
    /// attributes depending on size.
    pub evidence: serde_json::Value,

    /// Suggested remediation.
    pub remediation: Remediation,

    /// Extra attributes the rule wants on the `OTel` log record itself
    /// (e.g. `db.name`, `pgsleuth.replica.id`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub otel_attributes: BTreeMap<String, AttributeValue>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_finding() -> Finding {
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
            severity: Severity::High,
            fired_at: Utc.with_ymd_and_hms(2026, 6, 12, 15, 0, 0).unwrap(),
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

    #[test]
    fn finding_round_trips_through_json() {
        let f = sample_finding();
        let s = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&s).unwrap();
        assert_eq!(back.rule_id, f.rule_id);
        assert_eq!(back.schema_version, FINDING_SCHEMA_VERSION);
        assert_eq!(back.rule_version, 1);
        assert_eq!(back.pg_instance.role, PgRole::Replica);
        assert_eq!(back.remediation.knobs, vec!["max_wal_senders".to_string()]);
        assert_eq!(back.otel_attributes.len(), 1);
    }

    #[test]
    fn omits_empty_optional_collections_on_the_wire() {
        let mut f = sample_finding();
        f.otel_attributes.clear();
        f.remediation.knobs.clear();
        f.pg_instance.db_name = None;
        let s = serde_json::to_string(&f).unwrap();
        assert!(!s.contains("otel_attributes"));
        assert!(!s.contains("knobs"));
        assert!(!s.contains("db_name"));
    }

    #[test]
    fn schema_version_is_one() {
        // Tripwire: bumping this constant is a breaking change to the
        // brain↔agent wire contract. Update the brain consumers in lock-step.
        assert_eq!(FINDING_SCHEMA_VERSION, 1);
    }
}
