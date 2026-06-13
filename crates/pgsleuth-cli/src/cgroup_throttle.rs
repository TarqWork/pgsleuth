// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! `pgsleuth cgroup-throttle` runtime — Alarm 14.
//!
//! Polls `cpu.stat` on the local cgroup, tracks the delta of
//! `throttled_usec` per interval, fires a Finding when the throttled
//! time exceeds a sustained threshold (default 50 ms throttled per
//! second of wall-clock).
//!
//! The catalog spec calls for eBPF kprobes on `throttle_cfs_rq` /
//! `unthrottle_cfs_rq` for true per-window timing AND correlation
//! with backend P95 latency from #43. v0 ships the polling half
//! only; the kernel side and the AND-with-latency check land with
//! the rule engine. The catalog answer for #42 already documents
//! that Tier-3 isn't grantable in many managed-K8s environments
//! anyway, so the polling half remains the load-bearing detector
//! everywhere.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use pgsleuth_core::{
    AttributeValue, BreachState, ConsecutiveBreachCounter, Finding, PgInstanceRef, PgRole,
    Remediation, Severity, Tier, FINDING_SCHEMA_VERSION,
};
use pgsleuth_otel::Emitter;
use tokio::time::{interval, MissedTickBehavior};

/// One snapshot of the cgroup-v2 `cpu.stat` fields we care about.
///
/// Format excerpt (man cgroups(7)):
/// ```text
/// nr_periods    NNN
/// nr_throttled  NNN
/// throttled_usec NNN
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuStat {
    /// `nr_periods` — total CFS scheduling periods seen.
    pub nr_periods: u64,
    /// `nr_throttled` — periods in which the cgroup was throttled.
    pub nr_throttled: u64,
    /// `throttled_usec` — cumulative time the cgroup was throttled
    /// (microseconds).
    pub throttled_usec: u64,
}

impl CpuStat {
    /// Parse the contents of `cpu.stat`. Unknown / extra lines are
    /// ignored so cgroup variants that add fields stay forward-compat.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        let mut out = Self::default();
        for line in s.lines() {
            let mut it = line.split_whitespace();
            let Some(key) = it.next() else {
                continue;
            };
            let Some(val) = it.next() else {
                continue;
            };
            let Ok(n) = val.parse::<u64>() else {
                continue;
            };
            match key {
                "nr_periods" => out.nr_periods = n,
                "nr_throttled" => out.nr_throttled = n,
                "throttled_usec" => out.throttled_usec = n,
                _ => {}
            }
        }
        out
    }
}

/// Read `cpu.stat` from disk.
///
/// # Errors
///
/// Surfaces the underlying I/O error.
pub fn read_cpu_stat(path: &Path) -> Result<CpuStat> {
    let s = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(CpuStat::parse(&s))
}

/// Run the polling loop until cancelled.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    cpu_stat_path: PathBuf,
    interval_ms: u64,
    throttled_ms_per_sec_threshold: u64,
    fire_after: u32,
    pg_instance_id: &str,
    emitter: Option<&Emitter>,
) -> Result<()> {
    tracing::info!(
        path = %cpu_stat_path.display(),
        interval_ms,
        throttled_ms_per_sec_threshold,
        fire_after,
        "starting cgroup-throttle poller (rule cpu.cgroup.throttle)"
    );

    let mut tick = interval(Duration::from_millis(interval_ms));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tick.tick().await;

    let mut counter = ConsecutiveBreachCounter::default();
    let mut prev: Option<CpuStat> = None;

    loop {
        tick.tick().await;
        let cur = match read_cpu_stat(&cpu_stat_path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "cpu.stat read failed; skipping tick");
                continue;
            }
        };

        let breach = breach_value(prev.as_ref(), &cur, interval_ms);
        let breached = breach
            .as_ref()
            .is_some_and(|b| b.throttled_ms_per_sec > throttled_ms_per_sec_threshold);
        let state = counter.observe(breached, fire_after);
        tracing::info!(
            ?breach,
            ?state,
            cur_throttled_usec = cur.throttled_usec,
            "cgroup-throttle tick"
        );

        if let BreachState::JustFired { streak } = state {
            let Some(b) = breach else {
                prev = Some(cur);
                continue;
            };
            let finding = build_finding(
                pg_instance_id,
                &b,
                throttled_ms_per_sec_threshold,
                streak,
                interval_ms,
            );
            if let Some(em) = emitter {
                em.emit(&finding);
            }
            tracing::warn!("FINDING fired: {}", finding.summary);
        }

        prev = Some(cur);
    }
}

/// Computed per-interval breach quantities, surfaced into the
/// Finding's evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreachValue {
    /// Throttled microseconds in this interval (`cur - prev`).
    pub throttled_usec_delta: u64,
    /// Throttled milliseconds normalized per second of wall-clock —
    /// the value the threshold is in.
    pub throttled_ms_per_sec: u64,
    /// Periods this interval (`cur.nr_periods - prev.nr_periods`).
    pub periods_delta: u64,
    /// Throttled periods this interval.
    pub throttled_periods_delta: u64,
}

fn breach_value(prev: Option<&CpuStat>, cur: &CpuStat, interval_ms: u64) -> Option<BreachValue> {
    let p = prev?;
    let throttled_usec_delta = cur.throttled_usec.saturating_sub(p.throttled_usec);
    // throttled_usec / 1000 = throttled_ms; / interval_seconds.
    // interval_ms is in milliseconds; throttled_ms_per_sec =
    // (throttled_usec / 1_000) * (1_000 / interval_ms).
    let throttled_ms_per_sec = throttled_usec_delta.checked_div(interval_ms).unwrap_or(0);
    Some(BreachValue {
        throttled_usec_delta,
        throttled_ms_per_sec,
        periods_delta: cur.nr_periods.saturating_sub(p.nr_periods),
        throttled_periods_delta: cur.nr_throttled.saturating_sub(p.nr_throttled),
    })
}

fn build_finding(
    pg_instance: &str,
    b: &BreachValue,
    threshold: u64,
    streak: u32,
    interval_ms: u64,
) -> Finding {
    let mut otel_attributes = BTreeMap::new();
    otel_attributes.insert(
        "pgsleuth.cgroup.throttle.eBPF_correlation".to_string(),
        AttributeValue::Bool(false),
    );
    Finding {
        schema_version: FINDING_SCHEMA_VERSION,
        rule_id: "cpu.cgroup.throttle".to_string(),
        rule_version: 1,
        tier: Tier::Standard,
        severity: Severity::High,
        fired_at: Utc::now(),
        pg_instance: PgInstanceRef {
            id: pg_instance.to_string(),
            db_name: None,
            role: PgRole::Unknown,
        },
        summary: format!(
            "Cgroup throttled {}ms/sec > {}ms/sec threshold for {} consecutive {}ms intervals",
            b.throttled_ms_per_sec, threshold, streak, interval_ms
        ),
        evidence: serde_json::json!({
            "throttled_ms_per_sec": b.throttled_ms_per_sec,
            "throttled_usec_delta": b.throttled_usec_delta,
            "periods_delta": b.periods_delta,
            "throttled_periods_delta": b.throttled_periods_delta,
            "threshold_ms_per_sec": threshold,
            "streak_intervals": streak,
            "interval_ms": interval_ms,
            "eBPF_correlation": false,
        }),
        remediation: Remediation {
            text: "Raise the cgroup's CFS CPU quota or migrate to a node with more CPU \
                   headroom. Latency spikes correlated with throttle windows are root-cause; \
                   inside-PG metrics will look healthy."
                .to_string(),
            knobs: vec!["cpu.max".to_string(), "limits.cpu (K8s)".to_string()],
        },
        otel_attributes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_cpu_stat() {
        let s = "usage_usec 12345\nuser_usec 100\nsystem_usec 200\nnr_periods 1000\nnr_throttled 5\nthrottled_usec 250000\n";
        let parsed = CpuStat::parse(s);
        assert_eq!(parsed.nr_periods, 1000);
        assert_eq!(parsed.nr_throttled, 5);
        assert_eq!(parsed.throttled_usec, 250_000);
    }

    #[test]
    fn parses_with_extra_fields_safely() {
        let s = "nr_periods 1\nnr_throttled 0\nthrottled_usec 0\nfuture_field 99\n";
        let parsed = CpuStat::parse(s);
        assert_eq!(parsed.nr_periods, 1);
    }

    #[test]
    fn breach_value_normalises_to_ms_per_sec() {
        // 500 ms throttled in a 1000 ms interval = 500 ms/sec.
        let prev = CpuStat {
            nr_periods: 10,
            nr_throttled: 1,
            throttled_usec: 0,
        };
        let cur = CpuStat {
            nr_periods: 20,
            nr_throttled: 6,
            throttled_usec: 500_000,
        };
        let b = breach_value(Some(&prev), &cur, 1_000).unwrap();
        assert_eq!(b.throttled_ms_per_sec, 500);
        assert_eq!(b.periods_delta, 10);
        assert_eq!(b.throttled_periods_delta, 5);
    }

    #[test]
    fn breach_value_handles_no_prev() {
        let cur = CpuStat::default();
        assert!(breach_value(None, &cur, 1_000).is_none());
    }

    #[test]
    fn breach_value_handles_zero_interval() {
        let prev = CpuStat::default();
        let cur = CpuStat {
            throttled_usec: 100,
            ..CpuStat::default()
        };
        let b = breach_value(Some(&prev), &cur, 0).unwrap();
        assert_eq!(b.throttled_ms_per_sec, 0);
    }

    #[test]
    fn build_finding_carries_evidence() {
        let b = BreachValue {
            throttled_usec_delta: 60_000,
            throttled_ms_per_sec: 60,
            periods_delta: 10,
            throttled_periods_delta: 3,
        };
        let f = build_finding("prod-pg", &b, 50, 3, 1000);
        assert_eq!(f.rule_id, "cpu.cgroup.throttle");
        assert_eq!(f.evidence["throttled_ms_per_sec"], 60);
        assert_eq!(f.evidence["threshold_ms_per_sec"], 50);
    }
}
