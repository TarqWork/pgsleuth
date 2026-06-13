// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! `pg_stat_activity` polling collector.
//!
//! Point-in-time snapshot of all backend sessions. Unlike
//! `pg_stat_statements`, the view is **not** cumulative — each poll
//! returns the live state of every backend, so we emit gauges, not
//! deltas. Downstream rules (#44 — connection storm) consume the
//! snapshot directly.

use std::collections::BTreeMap;

use anyhow::{Context, Result};

/// Snapshot of `pg_stat_activity` at one poll instant.
///
/// All fields are gauges (current values) rather than counters; a
/// later tick replaces them outright.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionSnapshot {
    /// Total backend count (`pg_stat_activity` row count, minus the
    /// "background processes" rows where `backend_type != 'client backend'`
    /// — we count only client-facing sessions because that's what
    /// `pg_settings.max_connections` constrains).
    pub client_backends: u64,
    /// Count of sessions grouped by `state`
    /// (`active` / `idle` / `idle in transaction` / `idle in transaction (aborted)` /
    ///  `fastpath function call` / `disabled`). Keyed by the raw view
    /// string so callers don't lose any state the kernel adds in a
    /// future PG version.
    pub by_state: BTreeMap<String, u64>,
    /// Count of sessions grouped by `(wait_event_type, wait_event)`.
    /// Empty key pair means "not waiting on anything" — typically the
    /// majority of `active` backends.
    pub by_wait: BTreeMap<(String, String), u64>,
    /// Count of sessions whose `xact_start` is older than the
    /// long-transaction threshold passed to [`poll`].
    pub long_running_xacts: u64,
}

impl SessionSnapshot {
    /// Number of sessions in any "idle in transaction" state. Surfaced
    /// because it is the classic operator-facing red flag — a client
    /// holding row locks while idle.
    #[must_use]
    pub fn idle_in_xact(&self) -> u64 {
        let mut total = 0u64;
        for (state, count) in &self.by_state {
            if state.starts_with("idle in transaction") {
                total = total.saturating_add(*count);
            }
        }
        total
    }

    /// Number of `active` sessions waiting on a lock. Used directly by
    /// the connection-storm rule (#44) to distinguish "many active
    /// backends" from "many active backends fighting over locks".
    #[must_use]
    pub fn active_waiting_on_lock(&self) -> u64 {
        self.by_wait
            .iter()
            .filter(|((cat, _), _)| cat == "Lock")
            .map(|(_, c)| *c)
            .sum()
    }
}

/// Poll `pg_stat_activity` once. Sessions whose `xact_start` is older
/// than `long_xact_threshold_seconds` count toward
/// `long_running_xacts`.
///
/// # Errors
///
/// Surfaces the underlying SQL error if the view query fails.
pub async fn poll(
    client: &tokio_postgres::Client,
    long_xact_threshold_seconds: u64,
) -> Result<SessionSnapshot> {
    let row = client
        .query_one(
            "SELECT count(*)::int8 FROM pg_stat_activity WHERE backend_type = 'client backend'",
            &[],
        )
        .await
        .context("pg_stat_activity backend count query failed")?;
    let total: i64 = row.get(0);

    let state_rows = client
        .query(
            "SELECT COALESCE(state, '<null>')::text AS state, count(*)::int8 AS n \
             FROM pg_stat_activity \
             WHERE backend_type = 'client backend' \
             GROUP BY state",
            &[],
        )
        .await
        .context("pg_stat_activity state grouping failed")?;
    let mut by_state = BTreeMap::new();
    for r in state_rows {
        let state: String = r.get("state");
        let n: i64 = r.get("n");
        by_state.insert(state, u64::try_from(n).unwrap_or(0));
    }

    let wait_rows = client
        .query(
            "SELECT COALESCE(wait_event_type, '')::text AS we_type, \
                    COALESCE(wait_event,      '')::text AS we_name, \
                    count(*)::int8 AS n \
             FROM pg_stat_activity \
             WHERE backend_type = 'client backend' \
               AND state = 'active' \
             GROUP BY wait_event_type, wait_event",
            &[],
        )
        .await
        .context("pg_stat_activity wait_event grouping failed")?;
    let mut by_wait = BTreeMap::new();
    for r in wait_rows {
        let we_type: String = r.get("we_type");
        let we_name: String = r.get("we_name");
        let n: i64 = r.get("n");
        by_wait.insert((we_type, we_name), u64::try_from(n).unwrap_or(0));
    }

    // Long-running transactions: xact_start present + older than
    // threshold. Postgres exposes EXTRACT(EPOCH FROM ...) as float8.
    // Pass the threshold as an i8-cast-to-int8 parameter to dodge the
    // u64→f64 precision lint — the actual server-side comparison is
    // against a numeric anyway.
    let threshold_i64 = i64::try_from(long_xact_threshold_seconds).unwrap_or(i64::MAX);
    let long_row = client
        .query_one(
            "SELECT count(*)::int8 \
             FROM pg_stat_activity \
             WHERE backend_type = 'client backend' \
               AND xact_start IS NOT NULL \
               AND EXTRACT(EPOCH FROM (now() - xact_start)) > $1::int8",
            &[&threshold_i64],
        )
        .await
        .context("pg_stat_activity long_running_xacts query failed")?;
    let long_running_xacts: i64 = long_row.get(0);

    Ok(SessionSnapshot {
        client_backends: u64::try_from(total).unwrap_or(0),
        by_state,
        by_wait,
        long_running_xacts: u64::try_from(long_running_xacts).unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap_with_states(pairs: &[(&str, u64)]) -> SessionSnapshot {
        let mut s = SessionSnapshot::default();
        for (k, v) in pairs {
            s.by_state.insert((*k).to_string(), *v);
        }
        s
    }

    #[test]
    fn idle_in_xact_sums_both_variants() {
        let s = snap_with_states(&[
            ("idle in transaction", 3),
            ("idle in transaction (aborted)", 1),
            ("idle", 10),
            ("active", 5),
        ]);
        assert_eq!(s.idle_in_xact(), 4);
    }

    #[test]
    fn active_waiting_on_lock_filters_by_category() {
        let mut s = SessionSnapshot::default();
        s.by_wait
            .insert(("Lock".to_string(), "transactionid".to_string()), 2);
        s.by_wait
            .insert(("Lock".to_string(), "tuple".to_string()), 1);
        s.by_wait
            .insert(("IPC".to_string(), "MessageQueueSend".to_string()), 4);
        assert_eq!(s.active_waiting_on_lock(), 3);
    }

    #[test]
    fn idle_in_xact_zero_when_no_match() {
        let s = snap_with_states(&[("idle", 10), ("active", 5)]);
        assert_eq!(s.idle_in_xact(), 0);
    }
}
