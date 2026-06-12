// xtask for building eBPF program

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::process::Command;

#[derive(Debug, Parser)]
#[command(name = "xtask", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Build the kernel-side eBPF crate for `bpfel-unknown-none`.
    BuildEbpf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::BuildEbpf => {
            println!("Building eBPF program...");

            // Use cargo build-std to build the eBPF program
            let output = Command::new("cargo")
                .args([
                    "build",
                    "-Zbuild-std",
                    "--target",
                    "bpfel-unknown-none",
                    "--release",
                    "-p",
                    "pgsleuth-ebpf",
                ])
                .output()?;

            if !output.status.success() {
                eprintln!("Build failed:");
                eprintln!("{}", String::from_utf8_lossy(&output.stderr));
                anyhow::bail!("eBPF build failed");
            }

            println!("Build successful!");
            println!("Output: {}", String::from_utf8_lossy(&output.stdout));

            Ok(())
        }
    }
}
