// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! Postgres collectors.
//!
//! Each collector queries a specific set of `pg_stat_*` views and
//! produces *normalized samples* — typed Rust structs that the rule
//! engine (#28) will subscribe to. Today the cli wires them straight
//! into the `OTel` metrics emitter; when the engine lands, the
//! collector contracts here are stable and only the wiring changes.

pub mod stat_activity;
pub mod stat_statements;

/// Minor version + extension probing helpers shared across collectors.
pub mod pg_version {
    use anyhow::{Context, Result};

    /// Read `server_version_num` (e.g. `170002` for 17.2) and return
    /// the *major* version.
    ///
    /// # Errors
    ///
    /// Surfaces the underlying SQL error when `SHOW server_version_num`
    /// fails or returns a non-numeric value.
    pub async fn major(client: &tokio_postgres::Client) -> Result<u32> {
        let row = client
            .query_one("SHOW server_version_num", &[])
            .await
            .context("SHOW server_version_num failed")?;
        let s: String = row.get(0);
        let n: u32 = s
            .parse()
            .with_context(|| format!("server_version_num={s:?} did not parse"))?;
        Ok(n / 10_000)
    }
}
