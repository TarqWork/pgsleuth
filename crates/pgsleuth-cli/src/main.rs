// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! pgsleuth — command-line interface and agent runtime.
//!
//! Today this binary hosts the polling rules. Subcommand layout:
//!
//! * `pgsleuth temp-spill` — Alarm 12b (capacity-side temp-file
//!   spill, #47). Polls `$PGDATA/base/pgsql_tmp/` size and mount free
//!   space; emits a Finding when either threshold trips.
//! * `pgsleuth pg-stat-statements` — Tier-1 collector (#23). Polls
//!   `pg_stat_statements`, emits `pgsleuth.pg.stmt.*` `OTel` counters
//!   as deltas since the last poll.
//! * `pgsleuth version` — prints version + build info.

mod checkpoint_storm;
mod collect_pg_activity;
mod collect_pg_stmt;
mod connection_storm;
mod temp_spill;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pgsleuth_otel::{Emitter, EmitterConfig, MetricsEmitter};

use crate::temp_spill::TempSpillConfig;

#[derive(Parser)]
#[command(
    name = "pgsleuth",
    version,
    about = "Postgres observability that thinks like a senior DBA"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Print version and build info.
    Version,
    /// Alarm 12b — Temp-File Spill capacity poller (#47).
    TempSpill(TempSpillArgs),
    /// Tier-1 collector — `pg_stat_statements` polling (#23).
    PgStatStatements(PgStatStatementsArgs),
    /// Tier-1 collector — `pg_stat_activity` snapshot polling (#24).
    PgStatActivity(PgStatActivityArgs),
    /// Alarm 13 — Checkpoint storm classifier (#46).
    CheckpointStorm(CheckpointStormArgs),
    /// Alarm 05 — Connection storm (polling half; eBPF deferred) (#44).
    ConnectionStorm(ConnectionStormArgs),
}

#[derive(Parser, Debug)]
struct ConnectionStormArgs {
    /// Postgres libpq connection string.
    #[arg(
        long,
        default_value = "postgres://pgsleuth_agent:pgsleuth@localhost:5432/postgres"
    )]
    pg_conn: String,

    /// Poll interval in milliseconds.
    #[arg(long, default_value_t = 2_000)]
    interval_ms: u64,

    /// Fire if the live client-backend count exceeds this.
    #[arg(long, default_value_t = 100)]
    backend_threshold: u64,

    /// Sessions whose open transaction is older than this count toward
    /// `long_running_xacts` (passed through to the underlying
    /// `pg_stat_activity` query).
    #[arg(long, default_value_t = 60)]
    long_xact_threshold_seconds: u64,

    /// Emit a Finding after this many consecutive breaching intervals.
    #[arg(long, default_value_t = 3)]
    fire_after: u32,

    /// `OTLP`/gRPC endpoint for the Finding log emitter.
    #[arg(long, default_value = "")]
    otlp_endpoint: String,

    /// Identifier of the Postgres instance, written into the Finding.
    #[arg(long, default_value = "fixture-pg")]
    pg_instance: String,
}

#[derive(Parser, Debug)]
struct CheckpointStormArgs {
    /// Postgres libpq connection string.
    #[arg(
        long,
        default_value = "postgres://pgsleuth_agent:pgsleuth@localhost:5432/postgres"
    )]
    pg_conn: String,

    /// Poll interval in milliseconds.
    #[arg(long, default_value_t = 5_000)]
    interval_ms: u64,

    /// Fire a Finding when the dominant bucket recurs for this many
    /// consecutive intervals.
    #[arg(long, default_value_t = 3)]
    fire_after: u32,

    /// `OTLP`/gRPC endpoint for the Finding log emitter. Empty string
    /// disables `OTel` emission (Finding still logged via `tracing` at
    /// WARN).
    #[arg(long, default_value = "")]
    otlp_endpoint: String,

    /// Identifier of the Postgres instance, written into the Finding.
    #[arg(long, default_value = "fixture-pg")]
    pg_instance: String,
}

#[derive(Parser, Debug)]
struct PgStatActivityArgs {
    /// Postgres libpq connection string.
    #[arg(
        long,
        default_value = "postgres://pgsleuth_agent:pgsleuth@localhost:5432/postgres"
    )]
    pg_conn: String,

    /// Poll interval in milliseconds.
    #[arg(long, default_value_t = 5_000)]
    interval_ms: u64,

    /// Sessions whose open transaction is older than this count toward
    /// `long_running_xacts`.
    #[arg(long, default_value_t = 60)]
    long_xact_threshold_seconds: u64,
}

#[derive(Parser, Debug)]
struct PgStatStatementsArgs {
    /// Postgres libpq connection string.
    #[arg(
        long,
        default_value = "postgres://pgsleuth_agent:pgsleuth@localhost:5432/postgres"
    )]
    pg_conn: String,

    /// Poll interval in milliseconds.
    #[arg(long, default_value_t = 5_000)]
    interval_ms: u64,

    /// `OTLP`/gRPC endpoint for `pgsleuth.pg.stmt.*` counters. Empty
    /// string disables `OTel` emission (deltas still logged via
    /// `tracing` at INFO).
    #[arg(long, default_value = "")]
    otlp_endpoint: String,
}

#[derive(Parser, Debug)]
struct TempSpillArgs {
    /// Path to `$PGDATA`. Required unless `--pg-conn` is set, in which
    /// case the value is discovered via `SHOW data_directory`.
    #[arg(long)]
    pgdata: Option<PathBuf>,

    /// Postgres libpq connection string used to discover `$PGDATA` via
    /// `SHOW data_directory`. Ignored when `--pgdata` is passed.
    #[arg(long)]
    pg_conn: Option<String>,

    /// Aggregate `pgsql_tmp/` footprint threshold in megabytes. Fires
    /// when the directory's size exceeds this.
    #[arg(long, default_value_t = 10_240)]
    footprint_threshold_mb: u64,

    /// Free-space threshold as a percentage of the mount. Fires when
    /// available drops below. Set to 0 to disable the free-space check.
    #[arg(long, default_value_t = 10)]
    free_threshold_pct: u8,

    /// Poll interval in milliseconds.
    #[arg(long, default_value_t = 5_000)]
    interval_ms: u64,

    /// `OTLP`/gRPC endpoint for the Finding log emitter. Empty string
    /// disables `OTel` emission entirely (Finding still logged via
    /// `tracing` on `warn`).
    #[arg(long, default_value = "")]
    otlp_endpoint: String,

    /// Identifier of the Postgres instance, written into the Finding.
    #[arg(long, default_value = "fixture-pg")]
    pg_instance: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Version) | None => {
            println!("pgsleuth {} (pre-alpha)", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(Command::TempSpill(args)) => run_temp_spill(args).await,
        Some(Command::PgStatStatements(args)) => run_pg_stat_statements(args).await,
        Some(Command::PgStatActivity(args)) => {
            collect_pg_activity::run(
                &args.pg_conn,
                args.interval_ms,
                args.long_xact_threshold_seconds,
            )
            .await
        }
        Some(Command::CheckpointStorm(args)) => run_checkpoint_storm(args).await,
        Some(Command::ConnectionStorm(args)) => run_connection_storm(args).await,
    }
}

async fn run_connection_storm(args: ConnectionStormArgs) -> Result<()> {
    let emitter = if args.otlp_endpoint.is_empty() {
        tracing::info!("--otlp-endpoint empty; OTel emission disabled");
        None
    } else {
        let cfg = EmitterConfig {
            otlp_endpoint: args.otlp_endpoint.clone(),
            service_name: "pgsleuth-agent".to_string(),
            resource_attributes: BTreeMap::new(),
        };
        match Emitter::try_new(&cfg) {
            Ok(e) => Some(e),
            Err(e) => {
                tracing::warn!(error = %e, "OTel Emitter init failed; continuing without it");
                None
            }
        }
    };
    let result = connection_storm::run(
        &args.pg_conn,
        args.interval_ms,
        args.backend_threshold,
        args.long_xact_threshold_seconds,
        args.fire_after,
        &args.pg_instance,
        emitter.as_ref(),
    )
    .await;
    if let Some(e) = emitter {
        e.shutdown();
    }
    result
}

async fn run_checkpoint_storm(args: CheckpointStormArgs) -> Result<()> {
    let emitter = if args.otlp_endpoint.is_empty() {
        tracing::info!("--otlp-endpoint empty; OTel emission disabled");
        None
    } else {
        let cfg = EmitterConfig {
            otlp_endpoint: args.otlp_endpoint.clone(),
            service_name: "pgsleuth-agent".to_string(),
            resource_attributes: BTreeMap::new(),
        };
        match Emitter::try_new(&cfg) {
            Ok(e) => Some(e),
            Err(e) => {
                tracing::warn!(error = %e, "OTel Emitter init failed; continuing without it");
                None
            }
        }
    };
    let result = checkpoint_storm::run(
        &args.pg_conn,
        args.interval_ms,
        args.fire_after,
        &args.pg_instance,
        emitter.as_ref(),
    )
    .await;
    if let Some(e) = emitter {
        e.shutdown();
    }
    result
}

async fn run_pg_stat_statements(args: PgStatStatementsArgs) -> Result<()> {
    let metrics = if args.otlp_endpoint.is_empty() {
        tracing::info!("--otlp-endpoint empty; OTel metrics disabled");
        None
    } else {
        let cfg = EmitterConfig {
            otlp_endpoint: args.otlp_endpoint.clone(),
            service_name: "pgsleuth-agent".to_string(),
            resource_attributes: BTreeMap::new(),
        };
        match MetricsEmitter::try_new(&cfg) {
            Ok(m) => Some(m),
            Err(e) => {
                tracing::warn!(error = %e, "MetricsEmitter init failed; continuing without it");
                None
            }
        }
    };
    let result = collect_pg_stmt::run(&args.pg_conn, args.interval_ms, metrics.as_ref()).await;
    if let Some(m) = metrics {
        m.shutdown();
    }
    result
}

async fn run_temp_spill(args: TempSpillArgs) -> Result<()> {
    let pgdata = resolve_pgdata(&args).await?;
    let cfg = TempSpillConfig {
        pgdata,
        footprint_threshold_bytes: args.footprint_threshold_mb.saturating_mul(1_024 * 1_024),
        free_threshold_pct: args.free_threshold_pct,
        interval: Duration::from_millis(args.interval_ms),
        pg_instance_id: args.pg_instance,
    };

    let emitter = if args.otlp_endpoint.is_empty() {
        tracing::info!("--otlp-endpoint empty; OTel emission disabled");
        None
    } else {
        let otel_cfg = EmitterConfig {
            otlp_endpoint: args.otlp_endpoint.clone(),
            service_name: "pgsleuth-agent".to_string(),
            resource_attributes: BTreeMap::new(),
        };
        match Emitter::try_new(&otel_cfg) {
            Ok(e) => Some(e),
            Err(e) => {
                tracing::warn!(error = %e, "OTel Emitter init failed; continuing without it");
                None
            }
        }
    };

    let result = temp_spill::run(cfg, emitter.as_ref()).await;

    if let Some(e) = emitter {
        e.shutdown();
    }
    result
}

/// Resolve `$PGDATA`: `--pgdata` wins; otherwise pull `SHOW data_directory`
/// off the connection.
async fn resolve_pgdata(args: &TempSpillArgs) -> Result<PathBuf> {
    if let Some(p) = &args.pgdata {
        return Ok(p.clone());
    }
    let conn = args
        .pg_conn
        .as_deref()
        .context("either --pgdata or --pg-conn is required so the poller knows where to walk")?;
    tracing::info!(pg_conn = conn, "Discovering pgdata via SHOW data_directory");
    let (client, connection) = tokio_postgres::connect(conn, tokio_postgres::NoTls)
        .await
        .with_context(|| format!("Failed to connect to Postgres at {conn}"))?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::warn!(error = %e, "Postgres connection task ended");
        }
    });
    let row = client
        .query_one("SHOW data_directory", &[])
        .await
        .context("SHOW data_directory failed")?;
    let pgdata: String = row.get(0);
    tracing::info!(pgdata, "Discovered pgdata via libpq");
    Ok(PathBuf::from(pgdata))
}
