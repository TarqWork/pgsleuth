// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! pgsleuth — command-line interface and agent runtime.
//!
//! Pre-alpha: this binary currently does nothing useful. It exists so the
//! workspace builds and CI is green from week 1.

use clap::{Parser, Subcommand};

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
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Version) | None => {
            println!("pgsleuth {} (pre-alpha)", env!("CARGO_PKG_VERSION"));
        }
    }
}
