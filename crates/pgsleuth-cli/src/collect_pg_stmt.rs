// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! `pgsleuth collect pg-stat-statements` runtime.
//!
//! Probes the connection, polls `pg_stat_statements` on a tick,
//! diffs against the previous snapshot and emits the deltas as
//! `pgsleuth.pg.stmt.*` `OTel` counters.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use pgsleuth_otel::{MetricsEmitter, PgStmtDelta};
use pgsleuth_postgres::stat_statements::{self, ProbeOutcome, StatementSample, MIN_PG_VERSION};
use tokio::time::{interval, MissedTickBehavior};

/// Per-query state we need to remember across ticks for delta
/// computation. Cumulative counters can only go up; a decrease means
/// the extension was reset (or the row was evicted), so we reseed.
#[derive(Clone, Copy, Default)]
struct PrevCumulative {
    calls: u64,
    total_exec_time_ms: u64,
    rows: u64,
    shared_blks_hit: u64,
    shared_blks_read: u64,
}

/// Compute `cur - prev` clamped at 0 (reset detection).
fn delta(cur: u64, prev: u64) -> u64 {
    cur.saturating_sub(prev)
}

/// Floor an f64 into u64, clamping negatives to 0 and `+inf`/NaN to
/// `u64::MAX`. `pg_stat_statements.total_exec_time` is monotonically
/// non-negative in practice; the saturation handles the edge case
/// without surfacing the cast lints across this hot path.
fn f64_clamp_to_u64(v: f64) -> u64 {
    if !v.is_finite() {
        return u64::MAX;
    }
    if v <= 0.0 {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let n = v.floor() as u64;
    n
}

/// Run the polling loop until cancelled.
pub async fn run(pg_conn: &str, interval_ms: u64, emitter: Option<&MetricsEmitter>) -> Result<()> {
    tracing::info!(
        pg_conn,
        interval_ms,
        "starting pg_stat_statements collector"
    );

    let (client, connection) = tokio_postgres::connect(pg_conn, tokio_postgres::NoTls)
        .await
        .with_context(|| format!("Failed to connect to Postgres at {pg_conn}"))?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::warn!(error = %e, "Postgres connection task ended");
        }
    });

    match stat_statements::probe(&client).await? {
        ProbeOutcome::Ready => {}
        ProbeOutcome::ExtensionMissing => {
            tracing::error!(
                "pg_stat_statements is not installed; \
                 add it to shared_preload_libraries and run CREATE EXTENSION"
            );
            anyhow::bail!("pg_stat_statements not installed");
        }
        ProbeOutcome::PgVersionTooOld { actual } => {
            tracing::error!(
                actual_pg_major = actual,
                required_pg_major = MIN_PG_VERSION,
                "Postgres version too old for the pg_stat_statements collector"
            );
            anyhow::bail!("PG {actual} below collector minimum {MIN_PG_VERSION}");
        }
    }

    let mut prev: HashMap<i64, PrevCumulative> = HashMap::new();
    let mut tick = interval(Duration::from_millis(interval_ms));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tick.tick().await;

    loop {
        tick.tick().await;
        let samples = match stat_statements::poll(&client).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "pg_stat_statements poll failed; skipping tick");
                continue;
            }
        };
        emit_deltas(&samples, &mut prev, emitter);
    }
}

/// Pure function so the diff logic is unit-testable without an `OTel`
/// pipeline.
fn emit_deltas(
    samples: &[StatementSample],
    prev: &mut HashMap<i64, PrevCumulative>,
    emitter: Option<&MetricsEmitter>,
) {
    let mut total_rows = 0u64;
    for s in samples {
        let cur = PrevCumulative {
            calls: s.calls,
            // Truncate sub-millisecond exec time at u64; pg_stat_statements
            // can never report a negative — clamp at 0 if it ever does.
            total_exec_time_ms: f64_clamp_to_u64(s.total_exec_time_ms),
            rows: s.rows,
            shared_blks_hit: s.shared_blks_hit,
            shared_blks_read: s.shared_blks_read,
        };
        let previous = prev.get(&s.queryid).copied().unwrap_or_default();
        let calls_d = delta(cur.calls, previous.calls);
        let exec_d = delta(cur.total_exec_time_ms, previous.total_exec_time_ms);
        let rows_d = delta(cur.rows, previous.rows);
        let hit_d = delta(cur.shared_blks_hit, previous.shared_blks_hit);
        let read_d = delta(cur.shared_blks_read, previous.shared_blks_read);
        total_rows = total_rows.saturating_add(calls_d);

        if let Some(em) = emitter {
            em.record_pg_stmt_delta(&PgStmtDelta {
                queryid: s.queryid,
                database: &s.database,
                username: &s.username,
                calls: calls_d,
                exec_time_ms: exec_d,
                rows: rows_d,
                blks_hit: hit_d,
                blks_read: read_d,
            });
        }

        prev.insert(s.queryid, cur);
    }
    tracing::info!(
        statements = samples.len(),
        delta_calls = total_rows,
        "pg_stat_statements tick",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(queryid: i64, calls: u64, exec_ms: f64, rows: u64) -> StatementSample {
        StatementSample {
            queryid,
            database: "app".to_string(),
            username: "pgsleuth_agent".to_string(),
            calls,
            total_exec_time_ms: exec_ms,
            rows,
            shared_blks_hit: 0,
            shared_blks_read: 0,
        }
    }

    #[test]
    fn delta_saturates_on_reset() {
        // pg_stat_statements_reset() takes a per-statement row to zero.
        // A subsequent tick must NOT emit a negative-ish u64 wrap.
        assert_eq!(delta(0, 100), 0);
    }

    #[test]
    fn first_tick_emits_full_cumulative_as_delta() {
        // No previous → previous = 0 → delta = current. That seeds the
        // counter at the right value with a single artificial jump on
        // the very first emit; subsequent ticks are pure deltas.
        assert_eq!(delta(42, 0), 42);
    }

    #[test]
    fn emit_deltas_records_when_emitter_absent() {
        // Smoke-test the delta computation path without an emitter:
        // make sure the `prev` map is updated even when no metrics are
        // recorded.
        let mut prev = HashMap::new();
        let samples = vec![sample(1, 100, 10.5, 200), sample(2, 50, 5.0, 75)];
        emit_deltas(&samples, &mut prev, None);
        assert_eq!(prev.get(&1).map(|p| p.calls), Some(100));
        assert_eq!(prev.get(&2).map(|p| p.calls), Some(50));

        let next = vec![sample(1, 150, 20.0, 300), sample(2, 50, 5.0, 75)];
        emit_deltas(&next, &mut prev, None);
        assert_eq!(prev.get(&1).map(|p| p.calls), Some(150));
        // Queryid 2 unchanged → delta 0 expected; prev updated.
        assert_eq!(prev.get(&2).map(|p| p.calls), Some(50));
    }
}
