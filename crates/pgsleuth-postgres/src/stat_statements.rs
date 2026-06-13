// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! `pg_stat_statements` polling collector.
//!
//! Read-only role expected; the agent connection should run as
//! `pgsleuth_agent` (the fixture in #10 creates that role with
//! `pg_monitor` + `pg_read_all_stats`).
//!
//! Output shape is a `Vec<StatementSample>` per poll. Each sample is
//! the canonical view-row plus a stable `queryid` label downstream
//! collectors use as the cardinality key. The cli today wires these
//! straight into the `OTel` metric emitter; the rule engine (#28) will
//! subscribe to the same `Vec` shape later.

use anyhow::{Context, Result};

/// `pg_stat_statements` requires PG 13+ for the
/// `total_exec_time`/`total_plan_time` split this collector relies on.
pub const MIN_PG_VERSION: u32 = 13;

/// One row from `pg_stat_statements`, normalized into pgsleuth's
/// vocabulary. Values are **cumulative** (since extension reset);
/// downstream collectors / rules diff against a previous sample to get
/// rates.
#[derive(Debug, Clone, PartialEq)]
pub struct StatementSample {
    /// `pg_stat_statements.queryid` — stable hash of the normalized
    /// query text. Used as the cardinality key on `OTel` attributes
    /// (mapped to `pgsleuth.pg.queryid`).
    pub queryid: i64,
    /// Database name the statement ran in (`db.name` `OTel` semconv).
    pub database: String,
    /// Username that ran it. Often the operator wants to filter
    /// noisy `pgsleuth_agent` traffic out — we surface it rather than
    /// drop it.
    pub username: String,
    /// Cumulative number of calls.
    pub calls: u64,
    /// Cumulative total execution time in **milliseconds** (the view
    /// reports ms in PG 13+; we expose the unit explicitly so callers
    /// don't mix it with µs/ns).
    pub total_exec_time_ms: f64,
    /// Cumulative number of rows returned/affected.
    pub rows: u64,
    /// Cumulative shared-buffer blocks hit. Useful for buffer-cache
    /// hit-ratio rules later.
    pub shared_blks_hit: u64,
    /// Cumulative shared-buffer blocks read from disk.
    pub shared_blks_read: u64,
}

/// Probe outcome — distinguishes the three plausible failure modes so
/// the cli can downgrade gracefully:
///
/// 1. The extension is not installed — log and skip the collector.
/// 2. The PG major is below [`MIN_PG_VERSION`] — log and skip.
/// 3. Both green — collector is good to go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Extension and version both satisfy the collector's preconditions.
    Ready,
    /// `pg_stat_statements` is not installed (`CREATE EXTENSION` never run).
    ExtensionMissing,
    /// The Postgres major version is below [`MIN_PG_VERSION`].
    PgVersionTooOld {
        /// Actual major version detected on the server.
        actual: u32,
    },
}

/// Probe the connection: PG version + `pg_stat_statements` presence.
///
/// # Errors
///
/// Returns an error only if the connection is unusable — probe results
/// like "extension missing" are returned in the `Ok` branch so the
/// caller can decide whether to log-and-skip or hard-fail.
pub async fn probe(client: &tokio_postgres::Client) -> Result<ProbeOutcome> {
    let major = crate::pg_version::major(client).await?;
    if major < MIN_PG_VERSION {
        return Ok(ProbeOutcome::PgVersionTooOld { actual: major });
    }
    let row = client
        .query_one(
            "SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'",
            &[],
        )
        .await;
    match row {
        Ok(_) => Ok(ProbeOutcome::Ready),
        Err(e) if e.code().is_some_and(|c| c.code() == "42P01") => {
            // pg_extension not found — extremely unlikely on a real PG.
            Ok(ProbeOutcome::ExtensionMissing)
        }
        Err(_) => {
            // No row → query_one returns `WrongNumberOfRows`. The
            // extension just isn't installed.
            Ok(ProbeOutcome::ExtensionMissing)
        }
    }
}

/// Poll `pg_stat_statements` once and return one [`StatementSample`]
/// per row.
///
/// Caller is expected to have already verified [`probe`] returned
/// [`ProbeOutcome::Ready`] — calling this when the extension is missing
/// surfaces a Postgres error.
///
/// # Errors
///
/// Surfaces the underlying SQL error if the view query fails.
pub async fn poll(client: &tokio_postgres::Client) -> Result<Vec<StatementSample>> {
    // Joining to pg_database + pg_authid gets us human-readable labels
    // without an extra round-trip per row. `LEFT JOIN` so an orphaned
    // statement (db dropped while pg_stat_statements still retains the
    // row) still gets reported with an empty name rather than skipped.
    // Use pg_roles (public view) instead of pg_authid (superuser-only)
    // so the unprivileged pgsleuth_agent role can run this query.
    const SQL: &str = "
        SELECT
            s.queryid::int8                 AS queryid,
            COALESCE(d.datname, '')         AS database,
            COALESCE(r.rolname, '')         AS username,
            s.calls::int8                   AS calls,
            s.total_exec_time::float8       AS total_exec_time_ms,
            s.rows::int8                    AS rows,
            s.shared_blks_hit::int8         AS shared_blks_hit,
            s.shared_blks_read::int8        AS shared_blks_read
        FROM pg_stat_statements s
        LEFT JOIN pg_database d ON d.oid = s.dbid
        LEFT JOIN pg_roles    r ON r.oid = s.userid
        WHERE s.queryid IS NOT NULL
    ";

    let rows = client
        .query(SQL, &[])
        .await
        .context("pg_stat_statements query failed")?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let calls: i64 = row.get("calls");
        let rows_returned: i64 = row.get("rows");
        let hits: i64 = row.get("shared_blks_hit");
        let reads: i64 = row.get("shared_blks_read");
        out.push(StatementSample {
            queryid: row.get("queryid"),
            database: row.get("database"),
            username: row.get("username"),
            // Counters in pg_stat_statements are non-negative but the
            // view stores them as int8; clamp at 0 if a buggy
            // pg_stat_statements ever returns a negative.
            calls: u64::try_from(calls).unwrap_or(0),
            total_exec_time_ms: row.get("total_exec_time_ms"),
            rows: u64::try_from(rows_returned).unwrap_or(0),
            shared_blks_hit: u64::try_from(hits).unwrap_or(0),
            shared_blks_read: u64::try_from(reads).unwrap_or(0),
        });
    }
    Ok(out)
}
