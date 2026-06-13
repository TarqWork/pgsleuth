// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! `pgsleuth connection-storm` runtime — Alarm 05.
//!
//! Polls `pg_stat_activity` for the live client-backend count. Fires
//! a Finding when the count exceeds a threshold for N consecutive
//! intervals.
//!
//! The catalog calls for a *split* detector — connection count AND
//! eBPF-observed fork-rate / context-switch churn. v0 ships the
//! polling half only; the eBPF half (`sched_switch` + `inet_csk_accept`
//! tracepoints) lands with the rule engine. The Finding evidence
//! already carries a `churn_observed = false` flag so the brain can
//! tell which half tripped without re-deriving it.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use pgsleuth_core::{
    AttributeValue, BreachState, ConsecutiveBreachCounter, Finding, PgInstanceRef, PgRole,
    Remediation, Severity, Tier, FINDING_SCHEMA_VERSION,
};
use pgsleuth_otel::Emitter;
use pgsleuth_postgres::stat_activity;
use tokio::time::{interval, MissedTickBehavior};

/// Run the polling loop until cancelled.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    pg_conn: &str,
    interval_ms: u64,
    backend_threshold: u64,
    long_xact_threshold_seconds: u64,
    fire_after: u32,
    pg_instance_id: &str,
    emitter: Option<&Emitter>,
) -> Result<()> {
    tracing::info!(
        pg_conn,
        interval_ms,
        backend_threshold,
        fire_after,
        "starting connection-storm poller (rule storage.conn.storm)"
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

    let mut counter = ConsecutiveBreachCounter::default();

    loop {
        tick.tick().await;
        let snap = match stat_activity::poll(&client, long_xact_threshold_seconds).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "pg_stat_activity poll failed; skipping tick");
                continue;
            }
        };
        let breached = snap.client_backends > backend_threshold;
        let state = counter.observe(breached, fire_after);
        tracing::info!(
            client_backends = snap.client_backends,
            backend_threshold,
            ?state,
            "connection-storm tick"
        );
        if let BreachState::JustFired { streak } = state {
            let finding = build_finding(
                pg_instance_id,
                snap.client_backends,
                backend_threshold,
                streak,
                interval_ms,
            );
            if let Some(em) = emitter {
                em.emit(&finding);
            }
            tracing::warn!("FINDING fired: {}", finding.summary);
        }
    }
}

fn build_finding(
    pg_instance: &str,
    backends: u64,
    threshold: u64,
    streak: u32,
    interval_ms: u64,
) -> Finding {
    let mut otel_attributes = BTreeMap::new();
    otel_attributes.insert(
        "pgsleuth.conn.churn_observed".to_string(),
        AttributeValue::Bool(false),
    );
    Finding {
        schema_version: FINDING_SCHEMA_VERSION,
        rule_id: "storage.conn.storm".to_string(),
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
            "Client backend count {backends} > {threshold} for {streak} consecutive {interval_ms}ms intervals (eBPF churn signal pending)"
        ),
        evidence: serde_json::json!({
            "client_backends": backends,
            "backend_threshold": threshold,
            "streak_intervals": streak,
            "interval_ms": interval_ms,
            "churn_observed": false,
        }),
        remediation: Remediation {
            text: "Investigate connection pool sizing and any client retry storms. \
                   PG's process-per-connection model makes high concurrent counts \
                   expensive even when idle."
                .to_string(),
            knobs: vec![
                "max_connections".to_string(),
                "tcp_keepalives_idle".to_string(),
                "tcp_keepalives_interval".to_string(),
            ],
        },
        otel_attributes,
    }
}
