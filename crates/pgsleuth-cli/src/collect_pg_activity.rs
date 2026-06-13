// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! `pgsleuth pg-stat-activity` runtime.
//!
//! Polls `pg_stat_activity` on a tick and logs the snapshot. Future
//! rules (#44) subscribe to the same `SessionSnapshot` shape.

use std::time::Duration;

use anyhow::{Context, Result};
use pgsleuth_postgres::stat_activity::{self, SessionSnapshot};
use tokio::time::{interval, MissedTickBehavior};

/// Run the polling loop until cancelled. Each tick logs the current
/// snapshot at INFO; consumers (cli `tracing` subscriber, future rule
/// engine) pick it up from there.
pub async fn run(pg_conn: &str, interval_ms: u64, long_xact_threshold_seconds: u64) -> Result<()> {
    tracing::info!(
        pg_conn,
        interval_ms,
        long_xact_threshold_seconds,
        "starting pg_stat_activity collector"
    );

    let (client, connection) = tokio_postgres::connect(pg_conn, tokio_postgres::NoTls)
        .await
        .with_context(|| format!("Failed to connect to Postgres at {pg_conn}"))?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::warn!(error = %e, "Postgres connection task ended");
        }
    });

    let mut tick = interval(Duration::from_millis(interval_ms));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tick.tick().await;

    loop {
        tick.tick().await;
        let snap = match stat_activity::poll(&client, long_xact_threshold_seconds).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "pg_stat_activity poll failed; skipping tick");
                continue;
            }
        };
        log_snapshot(&snap);
    }
}

fn log_snapshot(snap: &SessionSnapshot) {
    tracing::info!(
        client_backends = snap.client_backends,
        idle_in_xact = snap.idle_in_xact(),
        active_waiting_on_lock = snap.active_waiting_on_lock(),
        long_running_xacts = snap.long_running_xacts,
        ?snap.by_state,
        "pg_stat_activity tick",
    );
}
