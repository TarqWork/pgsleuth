// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! `pg_stat_checkpointer` polling collector + checkpoint classifier.
//!
//! In PG 17 the checkpointer's counters moved out of
//! `pg_stat_bgwriter` into the dedicated `pg_stat_checkpointer` view.
//! This collector targets PG 17+; we don't backport to 13–16 yet.
//! The classifier turns each tick's deltas into one of four catalog
//! buckets (write-phase / sync-phase / forced / FPW-flood), and the
//! cli `checkpoint-storm` subcommand fires a Finding when the same
//! bucket recurs over N consecutive intervals.

use anyhow::{Context, Result};

/// Catalog (PG 17) requires this for the dedicated checkpointer view.
pub const MIN_PG_VERSION: u32 = 17;

/// Snapshot of `pg_stat_checkpointer` + relevant `pg_stat_wal` fields
/// at one poll instant. All values are **cumulative** since the
/// extension/server reset; the classifier diffs two snapshots.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CheckpointerSnapshot {
    /// `pg_stat_checkpointer.num_timed` — timed (background) checkpoints.
    pub num_timed: u64,
    /// `pg_stat_checkpointer.num_requested` — forced checkpoints (WAL
    /// limit / `pg_start_backup`).
    pub num_requested: u64,
    /// `pg_stat_checkpointer.write_time` (ms).
    pub write_time_ms: f64,
    /// `pg_stat_checkpointer.sync_time` (ms).
    pub sync_time_ms: f64,
    /// `pg_stat_checkpointer.buffers_written`.
    pub buffers_written: u64,
    /// `pg_stat_wal.wal_fpi` — full-page images written. Surfaced for
    /// FPW-flood classification.
    pub wal_fpi: u64,
}

/// Catalog classifications. See
/// `docs/research/Database Observability Alarms.md` § Alarm 13 for the
/// definitions and the per-bucket remediation knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckpointBucket {
    /// `write_time` >> `sync_time` — raise `checkpoint_completion_target`
    /// or lower `max_wal_size`.
    WritePhaseDominant,
    /// `sync_time` dominant — storage is slow; overlaps with #43.
    SyncPhaseDominant,
    /// `num_requested` delta > `num_timed` delta — WAL is filling
    /// faster than `checkpoint_timeout` can catch up.
    Forced,
    /// `wal_fpi` delta unusually large for the checkpoint count —
    /// checkpoints too frequent; extend `checkpoint_timeout`.
    FpwFlood,
}

impl CheckpointBucket {
    /// Catalog remediation prose attached to the Finding.
    #[must_use]
    pub fn recommendation_text(&self) -> &'static str {
        match self {
            Self::WritePhaseDominant => {
                "Write phase dominates — too many dirty pages. \
                 Raise checkpoint_completion_target or lower max_wal_size."
            }
            Self::SyncPhaseDominant => {
                "Sync phase dominates — storage is the bottleneck. \
                 Overlaps with the fsync-jitter alarm; investigate the WAL device."
            }
            Self::Forced => "WAL is filling faster than checkpoint_timeout — raise max_wal_size.",
            Self::FpwFlood => {
                "FPI traffic is high right after the checkpoint — checkpoints are too \
                 frequent. Extend checkpoint_timeout."
            }
        }
    }

    /// Catalog-recommended Postgres config knob list.
    #[must_use]
    pub fn knobs(&self) -> &'static [&'static str] {
        match self {
            Self::WritePhaseDominant => &["checkpoint_completion_target", "max_wal_size"],
            Self::SyncPhaseDominant => &["wal_sync_method", "synchronous_commit"],
            Self::Forced => &["max_wal_size"],
            Self::FpwFlood => &["checkpoint_timeout", "full_page_writes"],
        }
    }

    /// Short slug for `pgsleuth.checkpoint.bucket` `OTel` attribute.
    #[must_use]
    pub fn slug(&self) -> &'static str {
        match self {
            Self::WritePhaseDominant => "write_phase",
            Self::SyncPhaseDominant => "sync_phase",
            Self::Forced => "forced",
            Self::FpwFlood => "fpw_flood",
        }
    }
}

/// Classify the dominant bucket between two consecutive snapshots.
/// Returns `None` when no checkpoint completed in the interval
/// (rule shouldn't fire on quiet ticks).
///
/// Rules (catalog § Alarm 13):
/// 1. If a checkpoint completed AND `num_requested_delta >
///    num_timed_delta`, the **Forced** bucket wins regardless of
///    write/sync balance — it points at the root cause.
/// 2. Otherwise compare `write_time_delta` vs `sync_time_delta`.
///    The dominant side wins. The threshold is a 1.5× margin to
///    suppress noise when they're close.
/// 3. If neither phase dominates and `wal_fpi_delta` is high (>= 1k
///    pages per completed checkpoint), classify as **`FpwFlood`**.
pub fn classify(
    prev: &CheckpointerSnapshot,
    cur: &CheckpointerSnapshot,
) -> Option<CheckpointBucket> {
    let timed_d = cur.num_timed.saturating_sub(prev.num_timed);
    let req_d = cur.num_requested.saturating_sub(prev.num_requested);
    let checkpoints_in_interval = timed_d.saturating_add(req_d);
    if checkpoints_in_interval == 0 {
        return None;
    }

    if req_d > timed_d {
        return Some(CheckpointBucket::Forced);
    }

    let write_d = (cur.write_time_ms - prev.write_time_ms).max(0.0);
    let sync_d = (cur.sync_time_ms - prev.sync_time_ms).max(0.0);
    let fpi_d = cur.wal_fpi.saturating_sub(prev.wal_fpi);

    if write_d > sync_d * 1.5 {
        return Some(CheckpointBucket::WritePhaseDominant);
    }
    if sync_d > write_d * 1.5 {
        return Some(CheckpointBucket::SyncPhaseDominant);
    }
    // Neither phase clearly dominates — check FPI flood.
    if fpi_d / checkpoints_in_interval.max(1) >= 1_000 {
        return Some(CheckpointBucket::FpwFlood);
    }
    // No clear classification — quiet checkpoint, don't fire.
    None
}

/// Poll the relevant views and return one snapshot.
///
/// # Errors
///
/// Surfaces the underlying SQL error.
pub async fn poll(client: &tokio_postgres::Client) -> Result<CheckpointerSnapshot> {
    let row = client
        .query_one(
            "SELECT c.num_timed::int8           AS num_timed, \
                    c.num_requested::int8       AS num_requested, \
                    c.write_time::float8        AS write_time_ms, \
                    c.sync_time::float8         AS sync_time_ms, \
                    c.buffers_written::int8     AS buffers_written, \
                    w.wal_fpi::int8             AS wal_fpi \
             FROM pg_stat_checkpointer c, pg_stat_wal w",
            &[],
        )
        .await
        .context("pg_stat_checkpointer query failed")?;
    Ok(CheckpointerSnapshot {
        num_timed: u64::try_from(row.get::<_, i64>("num_timed")).unwrap_or(0),
        num_requested: u64::try_from(row.get::<_, i64>("num_requested")).unwrap_or(0),
        write_time_ms: row.get("write_time_ms"),
        sync_time_ms: row.get("sync_time_ms"),
        buffers_written: u64::try_from(row.get::<_, i64>("buffers_written")).unwrap_or(0),
        wal_fpi: u64::try_from(row.get::<_, i64>("wal_fpi")).unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(timed: u64, req: u64, wt: f64, st: f64, fpi: u64) -> CheckpointerSnapshot {
        CheckpointerSnapshot {
            num_timed: timed,
            num_requested: req,
            write_time_ms: wt,
            sync_time_ms: st,
            buffers_written: 0,
            wal_fpi: fpi,
        }
    }

    #[test]
    fn no_checkpoints_returns_none() {
        let p = snap(10, 0, 100.0, 50.0, 1_000);
        let c = snap(10, 0, 100.0, 50.0, 1_000);
        assert_eq!(classify(&p, &c), None);
    }

    #[test]
    fn forced_beats_phase_dominance() {
        // num_requested delta > num_timed delta wins even if write
        // is also high.
        let p = snap(10, 0, 100.0, 50.0, 0);
        let c = snap(11, 5, 500.0, 50.0, 0);
        assert_eq!(classify(&p, &c), Some(CheckpointBucket::Forced));
    }

    #[test]
    fn write_phase_dominates_at_1_5x_margin() {
        let p = snap(10, 0, 100.0, 50.0, 0);
        let c = snap(11, 0, 200.0, 50.0, 0); // write delta 100, sync 0
        assert_eq!(classify(&p, &c), Some(CheckpointBucket::WritePhaseDominant));
    }

    #[test]
    fn sync_phase_dominates_at_1_5x_margin() {
        let p = snap(10, 0, 50.0, 100.0, 0);
        let c = snap(11, 0, 60.0, 250.0, 0); // sync delta 150, write 10
        assert_eq!(classify(&p, &c), Some(CheckpointBucket::SyncPhaseDominant));
    }

    #[test]
    fn fpw_flood_when_phases_balanced_and_fpi_high() {
        let p = snap(10, 0, 100.0, 100.0, 0);
        let c = snap(11, 0, 110.0, 110.0, 2_000); // 2000 fpi / 1 cp
        assert_eq!(classify(&p, &c), Some(CheckpointBucket::FpwFlood));
    }

    #[test]
    fn balanced_phases_with_low_fpi_yields_no_classification() {
        let p = snap(10, 0, 100.0, 100.0, 0);
        let c = snap(11, 0, 110.0, 110.0, 50);
        assert_eq!(classify(&p, &c), None);
    }

    #[test]
    fn cumulative_resets_do_not_panic() {
        let p = snap(100, 50, 999.0, 999.0, 999);
        let c = snap(0, 0, 0.0, 0.0, 0); // pg_stat_reset()
                                         // No checkpoints delta in this view → None.
        assert_eq!(classify(&p, &c), None);
    }
}
