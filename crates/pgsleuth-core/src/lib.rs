// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! Core types for pgsleuth.
//!
//! This crate defines the shared vocabulary used by collectors, the rule
//! engine, and the OTel emitter. The most important type is [`Finding`] —
//! the structured output of any diagnostic check. The Python brain consumes
//! findings as JSON; it never sees the database directly.
//!
//! Pre-alpha: types here will change as the rule engine takes shape.

use serde::{Deserialize, Serialize};

/// Which collection tier produced this finding.
///
/// See the [tier model in the README](../../../README.md#tier-model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Postgres views only. Works everywhere including managed.
    Standard,
    /// Cloud provider APIs (CloudWatch, Cloud Logging). Managed only.
    CloudEnhanced,
    /// eBPF and on-host signals. Self-managed only.
    Deep,
}

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A diagnostic finding emitted by a rule.
///
/// The brain consumes findings as JSON. Findings are the only interface
/// between the agent (Rust) and the brain (Python).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identifier for the rule (e.g. `"replica.lag.high"`).
    pub rule_id: String,
    pub tier: Tier,
    pub severity: Severity,
    /// Human-readable summary. The brain may rewrite this.
    pub summary: String,
    /// Structured details — rule-specific JSON the brain can reason over.
    pub details: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_round_trips_through_json() {
        let f = Finding {
            rule_id: "replica.lag.high".to_string(),
            tier: Tier::Standard,
            severity: Severity::High,
            summary: "Replica lag exceeds threshold".to_string(),
            details: serde_json::json!({ "lag_seconds": 42 }),
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&s).unwrap();
        assert_eq!(back.rule_id, f.rule_id);
    }
}
