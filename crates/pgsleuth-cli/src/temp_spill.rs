// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! Alarm 12b: Temp-File Spill — Capacity (#47).
//!
//! Polls `$PGDATA/base/pgsql_tmp/` size and free space on its mount.
//! Fires when either dimension breaches a configured threshold:
//!
//! * aggregate footprint > `footprint_threshold_bytes`, or
//! * free space < `free_threshold_pct` (percent of total).
//!
//! This is the SRE-facing capacity alarm; the per-query attribution
//! alarm (12a, eBPF-based) lives separately (#45). Both rules share
//! the `storage.temp_spill.*` rule-id namespace.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use nix::sys::statvfs::statvfs;
use pgsleuth_core::{
    AttributeValue, Finding, PgInstanceRef, PgRole, Remediation, Severity, Tier,
    FINDING_SCHEMA_VERSION,
};
use pgsleuth_otel::Emitter;
use tokio::time::{interval, MissedTickBehavior};
use walkdir::WalkDir;

/// Self-contained config for one run of the capacity poller.
pub struct TempSpillConfig {
    /// Path to `$PGDATA`. The poller walks `<pgdata>/base/pgsql_tmp/`.
    pub pgdata: PathBuf,
    /// Footprint trigger — fires when the aggregate size of
    /// `pgsql_tmp/` exceeds this.
    pub footprint_threshold_bytes: u64,
    /// Free-space trigger — fires when free space on the mount drops
    /// below this percentage of the total. 0 disables the trigger.
    pub free_threshold_pct: u8,
    /// Poll cadence.
    pub interval: Duration,
    /// Identifier of the Postgres instance, written into the Finding.
    pub pg_instance_id: String,
}

/// One snapshot of the temp-spill state.
// `_bytes` postfix on every field is intentional — these are all
// byte-counts and the suffix makes the unit explicit at the call site.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TempSpillSample {
    /// Sum of file sizes under `pgsql_tmp/`. Excludes the directory's
    /// own block size; matches `du -sb` close enough for the alarm's
    /// purpose.
    pub footprint_bytes: u64,
    /// Total bytes on the mount point (from `statvfs.f_blocks * f_frsize`).
    pub mount_total_bytes: u64,
    /// Free bytes available to non-root processes
    /// (`statvfs.f_bavail * f_frsize`). We deliberately use `f_bavail`
    /// rather than `f_bfree` because Postgres runs unprivileged.
    pub mount_available_bytes: u64,
}

impl TempSpillSample {
    /// Free percentage, integer-rounded. Returns 100 when total is 0
    /// (degenerate; would also trigger before we get here).
    #[must_use]
    pub fn free_pct(&self) -> u8 {
        if self.mount_total_bytes == 0 {
            return 100;
        }
        // u128 arithmetic to avoid overflow on multi-TB volumes.
        let pct = u128::from(self.mount_available_bytes).saturating_mul(100)
            / u128::from(self.mount_total_bytes);
        // Saturate at u8::MAX; in practice pct ≤ 100.
        u8::try_from(pct).unwrap_or(u8::MAX)
    }

    /// Whether this sample breaches the configured thresholds. Either
    /// the footprint OR the free-space rule is enough to fire.
    #[must_use]
    pub fn breaches(&self, cfg: &TempSpillConfig) -> Option<BreachReason> {
        if self.footprint_bytes > cfg.footprint_threshold_bytes {
            return Some(BreachReason::Footprint {
                bytes: self.footprint_bytes,
                threshold_bytes: cfg.footprint_threshold_bytes,
            });
        }
        if cfg.free_threshold_pct > 0 && self.free_pct() < cfg.free_threshold_pct {
            return Some(BreachReason::FreeSpace {
                free_pct: self.free_pct(),
                threshold_pct: cfg.free_threshold_pct,
            });
        }
        None
    }
}

/// Which threshold tripped. Reflected in the Finding's `evidence`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreachReason {
    /// Aggregate footprint of `pgsql_tmp/` exceeded `threshold_bytes`.
    Footprint {
        /// Current size in bytes.
        bytes: u64,
        /// Configured trigger threshold.
        threshold_bytes: u64,
    },
    /// Free space on the mount fell below `threshold_pct`.
    FreeSpace {
        /// Current free %.
        free_pct: u8,
        /// Configured trigger %.
        threshold_pct: u8,
    },
}

/// Walk `<pgdata>/base/pgsql_tmp/` summing file sizes. Returns 0 if
/// the directory doesn't exist (no spill activity since boot). Walk
/// errors and per-file `metadata()` failures are folded into the
/// partial sum — under concurrent unlinks this is the safe choice.
fn footprint(pgdata: &Path) -> u64 {
    let tmp_dir = pgdata.join("base/pgsql_tmp");
    if !tmp_dir.exists() {
        return 0;
    }
    let mut total: u64 = 0;
    for entry in WalkDir::new(&tmp_dir).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            if let Ok(meta) = entry.metadata() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

/// Stat the mount that holds `pgsql_tmp/` (or, when the dir doesn't
/// exist yet, the `base/` parent) and return total + available bytes.
fn mount_capacity(pgdata: &Path) -> Result<(u64, u64)> {
    let tmp_dir = pgdata.join("base/pgsql_tmp");
    let target = if tmp_dir.exists() {
        tmp_dir
    } else {
        pgdata.join("base")
    };
    let v = statvfs(&target).with_context(|| format!("statvfs({}) failed", target.display()))?;
    let frsize = v.fragment_size();
    let total = frsize.saturating_mul(v.blocks());
    let available = frsize.saturating_mul(v.blocks_available());
    Ok((total, available))
}

/// Take one snapshot — combine `du`-equivalent and `df`-equivalent.
///
/// # Errors
///
/// Returns an error if statvfs fails. Footprint walk errors are
/// folded into a partial sum rather than surfaced.
pub fn sample(pgdata: &Path) -> Result<TempSpillSample> {
    let footprint_bytes = footprint(pgdata);
    let (total, available) = mount_capacity(pgdata)?;
    Ok(TempSpillSample {
        footprint_bytes,
        mount_total_bytes: total,
        mount_available_bytes: available,
    })
}

/// Run the polling loop until the future is cancelled (typically via
/// SIGINT in the caller). Each tick: snapshot → check threshold → if
/// breach, emit Finding via the supplied [`Emitter`] (when present).
pub async fn run(cfg: TempSpillConfig, emitter: Option<&Emitter>) -> Result<()> {
    tracing::info!(
        pgdata = %cfg.pgdata.display(),
        footprint_threshold_bytes = cfg.footprint_threshold_bytes,
        free_threshold_pct = cfg.free_threshold_pct,
        interval_ms = u64::try_from(cfg.interval.as_millis()).unwrap_or(u64::MAX),
        "starting temp-spill capacity poller (rule storage.temp_spill.capacity)",
    );

    let mut tick = interval(cfg.interval);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tick.tick().await;

    // Single-fire latch: emit one Finding per breach episode. Reset
    // when the next sample comes back under threshold.
    let mut firing = false;

    loop {
        tick.tick().await;
        let snap = match sample(&cfg.pgdata) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "temp-spill sample failed; skipping tick");
                continue;
            }
        };
        let breach = snap.breaches(&cfg);
        tracing::info!(
            footprint_bytes = snap.footprint_bytes,
            free_pct = snap.free_pct(),
            firing,
            breach_reason = ?breach,
            "temp-spill tick",
        );

        match (breach, firing) {
            (Some(reason), false) => {
                let finding = build_finding(&cfg, &snap, reason);
                if let Some(em) = emitter {
                    em.emit(&finding);
                }
                tracing::warn!("FINDING fired: {}", finding.summary);
                firing = true;
            }
            (None, true) => {
                tracing::info!("temp-spill back under threshold; re-arming");
                firing = false;
            }
            _ => {}
        }
    }
}

fn build_finding(cfg: &TempSpillConfig, snap: &TempSpillSample, reason: BreachReason) -> Finding {
    let (rule_suffix, summary, evidence) = match reason {
        BreachReason::Footprint {
            bytes,
            threshold_bytes,
        } => (
            "footprint",
            format!(
                "pgsql_tmp/ footprint {} bytes > {} bytes threshold (free={}%, total={} bytes)",
                bytes,
                threshold_bytes,
                snap.free_pct(),
                snap.mount_total_bytes
            ),
            serde_json::json!({
                "trigger": "footprint",
                "footprint_bytes": bytes,
                "footprint_threshold_bytes": threshold_bytes,
                "mount_total_bytes": snap.mount_total_bytes,
                "mount_available_bytes": snap.mount_available_bytes,
                "free_pct": snap.free_pct(),
            }),
        ),
        BreachReason::FreeSpace {
            free_pct,
            threshold_pct,
        } => (
            "free_space",
            format!(
                "Free space {}% < {}% threshold on pgsql_tmp/ mount (footprint={} bytes, total={} bytes)",
                free_pct,
                threshold_pct,
                snap.footprint_bytes,
                snap.mount_total_bytes
            ),
            serde_json::json!({
                "trigger": "free_space",
                "free_pct": free_pct,
                "free_threshold_pct": threshold_pct,
                "mount_available_bytes": snap.mount_available_bytes,
                "mount_total_bytes": snap.mount_total_bytes,
                "footprint_bytes": snap.footprint_bytes,
            }),
        ),
    };

    let mut otel_attributes = BTreeMap::new();
    otel_attributes.insert(
        "pgsleuth.pgdata".to_string(),
        AttributeValue::String(cfg.pgdata.display().to_string()),
    );
    otel_attributes.insert(
        "pgsleuth.temp_spill.trigger".to_string(),
        AttributeValue::String(rule_suffix.to_string()),
    );

    Finding {
        schema_version: FINDING_SCHEMA_VERSION,
        rule_id: "storage.temp_spill.capacity".to_string(),
        rule_version: 1,
        tier: Tier::Standard,
        severity: Severity::High,
        fired_at: Utc::now(),
        pg_instance: PgInstanceRef {
            id: cfg.pg_instance_id.clone(),
            db_name: None,
            role: PgRole::Unknown,
        },
        summary,
        evidence,
        remediation: Remediation {
            text: "Investigate the queries causing the spill (`pg_stat_database.temp_bytes`, \
                   `log_temp_files`). Resize the temp tablespace volume if traffic is \
                   expected to grow. Consider raising `work_mem` for the offending sessions \
                   to keep sorts/hashes in memory."
                .to_string(),
            knobs: vec![
                "work_mem".to_string(),
                "temp_tablespaces".to_string(),
                "temp_file_limit".to_string(),
            ],
        },
        otel_attributes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(footprint_threshold: u64, free_threshold: u8) -> TempSpillConfig {
        TempSpillConfig {
            pgdata: PathBuf::from("/tmp/pgdata-stub"),
            footprint_threshold_bytes: footprint_threshold,
            free_threshold_pct: free_threshold,
            interval: Duration::from_millis(100),
            pg_instance_id: "fixture-pg".to_string(),
        }
    }

    fn snap(footprint: u64, total: u64, available: u64) -> TempSpillSample {
        TempSpillSample {
            footprint_bytes: footprint,
            mount_total_bytes: total,
            mount_available_bytes: available,
        }
    }

    #[test]
    fn footprint_breach_takes_priority_when_both_trip() {
        let c = cfg(1_000, 50);
        // Both thresholds are violated; footprint reason wins because
        // it is checked first and the trigger string in the Finding
        // reflects the most actionable cause.
        let s = snap(2_000, 100_000, 10_000);
        assert!(matches!(
            s.breaches(&c),
            Some(BreachReason::Footprint { .. })
        ));
    }

    #[test]
    fn free_space_breach_fires_when_footprint_is_fine() {
        let c = cfg(u64::MAX, 50);
        let s = snap(0, 100_000, 10_000); // 10% free, < 50%
        assert!(matches!(
            s.breaches(&c),
            Some(BreachReason::FreeSpace { .. })
        ));
    }

    #[test]
    fn no_breach_below_both_thresholds() {
        let c = cfg(1_000, 10);
        let s = snap(500, 100_000, 80_000); // 80% free
        assert!(s.breaches(&c).is_none());
    }

    #[test]
    fn free_threshold_zero_disables_free_check() {
        let c = cfg(u64::MAX, 0);
        // 0% free would obviously fire if the check were on.
        let s = snap(0, 100_000, 0);
        assert!(s.breaches(&c).is_none());
    }

    #[test]
    fn free_pct_handles_zero_total_without_panic() {
        let s = snap(0, 0, 0);
        assert_eq!(s.free_pct(), 100);
    }

    #[test]
    fn free_pct_correct_for_typical_values() {
        let s = snap(0, 100, 25);
        assert_eq!(s.free_pct(), 25);
    }

    #[test]
    fn build_finding_carries_evidence_and_remediation() {
        let c = cfg(1_000, 10);
        let s = snap(2_000, 1_000_000, 500_000);
        let r = BreachReason::Footprint {
            bytes: s.footprint_bytes,
            threshold_bytes: c.footprint_threshold_bytes,
        };
        let f = build_finding(&c, &s, r);
        assert_eq!(f.rule_id, "storage.temp_spill.capacity");
        assert!(matches!(f.tier, Tier::Standard));
        assert!(matches!(f.severity, Severity::High));
        assert_eq!(f.evidence["trigger"], "footprint");
        assert_eq!(f.evidence["footprint_bytes"], 2_000);
        assert!(f.remediation.knobs.iter().any(|k| k == "work_mem"));
    }

    #[test]
    fn build_finding_free_space_variant_uses_free_trigger() {
        let c = cfg(u64::MAX, 50);
        let s = snap(100, 1_000_000, 100_000);
        let r = BreachReason::FreeSpace {
            free_pct: 10,
            threshold_pct: 50,
        };
        let f = build_finding(&c, &s, r);
        assert_eq!(f.evidence["trigger"], "free_space");
        assert_eq!(f.evidence["free_pct"], 10);
    }
}
