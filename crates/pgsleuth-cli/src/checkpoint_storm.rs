// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! `pgsleuth checkpoint-storm` runtime — Alarm 13.
//!
//! Polls `pg_stat_checkpointer` / `pg_stat_wal`, classifies each
//! interval's deltas into a [`CheckpointBucket`], fires a Finding
//! when the same bucket recurs over N consecutive intervals
//! (dominant-pattern recurrence). The Finding payload carries the
//! catalog-recommended config knobs so the operator gets a concrete
//! action, not just "checkpoint was slow".

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use pgsleuth_core::{
    AttributeValue, Finding, PgInstanceRef, PgRole, Remediation, Severity, Tier,
    FINDING_SCHEMA_VERSION,
};
use pgsleuth_otel::Emitter;
use pgsleuth_postgres::pg_version;
use pgsleuth_postgres::stat_checkpointer::{
    self, CheckpointBucket, CheckpointerSnapshot, MIN_PG_VERSION,
};
use tokio::time::{interval, MissedTickBehavior};

/// Tracks consecutive ticks classified as the same bucket. Fires on
/// the **transition** to >= `fire_after`; subsequent same-bucket ticks
/// stay quiet. A bucket change or a no-classification tick re-arms.
#[derive(Default)]
pub struct DominantStreak {
    current: Option<CheckpointBucket>,
    streak: u32,
    fired_for: Option<CheckpointBucket>,
}

/// Outcome of feeding the streak one classification.
#[derive(Debug, PartialEq, Eq)]
pub enum StreakState {
    /// Streak building; below `fire_after`.
    Building {
        /// The bucket whose streak is being built.
        bucket: CheckpointBucket,
        /// Length of the current streak.
        streak: u32,
    },
    /// Streak just reached `fire_after` for this bucket.
    JustFired {
        /// The bucket whose recurrence triggered the fire.
        bucket: CheckpointBucket,
        /// Length of the current streak.
        streak: u32,
    },
    /// Same bucket as last fire — keep quiet.
    StillFiring {
        /// The bucket whose recurrence is still in effect.
        bucket: CheckpointBucket,
        /// Length of the current streak.
        streak: u32,
    },
    /// This interval did not classify into any bucket. Streak unchanged.
    NoClassification,
}

impl DominantStreak {
    /// Feed one interval's classification.
    pub fn observe(&mut self, bucket: Option<CheckpointBucket>, fire_after: u32) -> StreakState {
        let Some(b) = bucket else {
            return StreakState::NoClassification;
        };
        if self.current == Some(b) {
            self.streak = self.streak.saturating_add(1);
        } else {
            self.current = Some(b);
            self.streak = 1;
            self.fired_for = None;
        }
        if self.streak < fire_after {
            return StreakState::Building {
                bucket: b,
                streak: self.streak,
            };
        }
        if self.fired_for == Some(b) {
            StreakState::StillFiring {
                bucket: b,
                streak: self.streak,
            }
        } else {
            self.fired_for = Some(b);
            StreakState::JustFired {
                bucket: b,
                streak: self.streak,
            }
        }
    }
}

/// Run the polling loop until cancelled.
pub async fn run(
    pg_conn: &str,
    interval_ms: u64,
    fire_after: u32,
    pg_instance_id: &str,
    emitter: Option<&Emitter>,
) -> Result<()> {
    tracing::info!(
        pg_conn,
        interval_ms,
        fire_after,
        "starting checkpoint-storm collector (rule storage.checkpoint.storm)"
    );

    let (client, connection) = tokio_postgres::connect(pg_conn, tokio_postgres::NoTls)
        .await
        .with_context(|| format!("Failed to connect to Postgres at {pg_conn}"))?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::warn!(error = %e, "Postgres connection task ended");
        }
    });

    let major = pg_version::major(&client).await?;
    if major < MIN_PG_VERSION {
        tracing::error!(
            actual_pg_major = major,
            required_pg_major = MIN_PG_VERSION,
            "checkpoint-storm needs pg_stat_checkpointer (PG 17+)"
        );
        anyhow::bail!("PG {major} below collector minimum {MIN_PG_VERSION}");
    }

    let mut tick = interval(Duration::from_millis(interval_ms));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tick.tick().await;

    let mut prev: Option<CheckpointerSnapshot> = None;
    let mut streak = DominantStreak::default();

    loop {
        tick.tick().await;
        let cur = match stat_checkpointer::poll(&client).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "checkpointer poll failed; skipping tick");
                continue;
            }
        };
        let bucket = prev
            .as_ref()
            .and_then(|p| stat_checkpointer::classify(p, &cur));
        let state = streak.observe(bucket, fire_after);
        tracing::info!(
            ?bucket,
            ?state,
            cur_timed = cur.num_timed,
            cur_requested = cur.num_requested,
            "checkpoint-storm tick"
        );
        if let StreakState::JustFired {
            bucket: b,
            streak: s,
        } = state
        {
            let finding = build_finding(pg_instance_id, b, s, interval_ms);
            if let Some(em) = emitter {
                em.emit(&finding);
            }
            tracing::warn!("FINDING fired: {}", finding.summary);
        }
        prev = Some(cur);
    }
}

fn build_finding(
    pg_instance: &str,
    bucket: CheckpointBucket,
    streak: u32,
    interval_ms: u64,
) -> Finding {
    let mut otel_attributes = BTreeMap::new();
    otel_attributes.insert(
        "pgsleuth.checkpoint.bucket".to_string(),
        AttributeValue::String(bucket.slug().to_string()),
    );
    Finding {
        schema_version: FINDING_SCHEMA_VERSION,
        rule_id: "storage.checkpoint.storm".to_string(),
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
            "Checkpoint storm — `{}` bucket dominant for {} consecutive {}ms intervals",
            bucket.slug(),
            streak,
            interval_ms,
        ),
        evidence: serde_json::json!({
            "bucket": bucket.slug(),
            "streak_intervals": streak,
            "interval_ms": interval_ms,
        }),
        remediation: Remediation {
            text: bucket.recommendation_text().to_string(),
            knobs: bucket.knobs().iter().map(|s| (*s).to_string()).collect(),
        },
        otel_attributes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streak_fires_after_n_same_buckets() {
        let mut s = DominantStreak::default();
        let b = CheckpointBucket::WritePhaseDominant;
        assert_eq!(
            s.observe(Some(b), 3),
            StreakState::Building {
                bucket: b,
                streak: 1
            }
        );
        assert_eq!(
            s.observe(Some(b), 3),
            StreakState::Building {
                bucket: b,
                streak: 2
            }
        );
        assert_eq!(
            s.observe(Some(b), 3),
            StreakState::JustFired {
                bucket: b,
                streak: 3
            }
        );
        assert_eq!(
            s.observe(Some(b), 3),
            StreakState::StillFiring {
                bucket: b,
                streak: 4
            }
        );
    }

    #[test]
    fn bucket_change_resets_streak() {
        let mut s = DominantStreak::default();
        let w = CheckpointBucket::WritePhaseDominant;
        let f = CheckpointBucket::Forced;
        s.observe(Some(w), 2);
        s.observe(Some(w), 2);
        // First two were build/just-fired; now flip bucket.
        assert_eq!(
            s.observe(Some(f), 2),
            StreakState::Building {
                bucket: f,
                streak: 1
            }
        );
    }

    #[test]
    fn no_classification_does_not_change_state() {
        let mut s = DominantStreak::default();
        let b = CheckpointBucket::Forced;
        s.observe(Some(b), 3);
        s.observe(None, 3);
        // Still building; same bucket on next observe continues streak.
        assert_eq!(
            s.observe(Some(b), 3),
            StreakState::Building {
                bucket: b,
                streak: 2
            }
        );
    }
}
