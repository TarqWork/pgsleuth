// Userspace loader for pgsleuth eBPF POC
// Loads kprobe and reads ring buffer events filtered by a configurable name.

use anyhow::{Context, Result};
use aya::{
    maps::{Array, RingBuf},
    programs::KProbe,
    Ebpf,
};
use clap::Parser;
use log::{info, warn};
use pgsleuth_ebpf_common::{FilterConfig, TraceEvent};
use tokio::io::unix::AsyncFd;
use tokio::signal;

#[derive(Debug, Parser)]
#[command(name = "pgsleuth-ebpf-loader", version, about)]
struct Args {
    /// Path to the compiled BPF object
    #[arg(long, default_value = "/build/pgsleuth-ebpf")]
    bpf_object: String,

    /// Process name to filter for (max 15 characters)
    #[arg(long, default_value = "")]
    name: String,

    /// PID to filter for. Overrides the postmaster PID discovered via
    /// `--pg-conn` when present.
    #[arg(long)]
    pid: Option<u32>,

    /// Cgroup ID to filter for.
    #[arg(long)]
    cgroup_id: Option<u64>,

    /// Postgres libpq connection string. The loader connects at startup
    /// and runs `SELECT pgsleuth_wal_device(), pgsleuth_postmaster_pid();`
    /// against the pgsleuth extension. The postmaster PID is used as the
    /// default for `--pid` when neither `--pid` nor `--cgroup-id` is
    /// passed explicitly. Pass `--pg-conn ''` (empty string) to skip the
    /// query — useful when the extension is not installed.
    #[arg(long, default_value = "postgres://postgres@localhost/postgres")]
    pg_conn: String,
}

/// Result of the startup pg-ext query.
struct PgDiscovery {
    /// Output of `pgsleuth_postmaster_pid()` — the PID of the Postgres
    /// supervisor process. Used as the default PID filter. The
    /// `pgsleuth_wal_device()` result is logged inside
    /// [`discover_via_pg_ext`] but not returned; #18 will re-add a
    /// `dev_t` field here when it wires that filter into the kernel.
    postmaster_pid: i32,
}

/// Connect to Postgres, query the pgsleuth extension's two helper
/// functions, log the result, and return the structured values.
async fn discover_via_pg_ext(pg_conn: &str) -> Result<PgDiscovery> {
    info!("Connecting to Postgres via: {pg_conn}");
    let (client, connection) = tokio_postgres::connect(pg_conn, tokio_postgres::NoTls)
        .await
        .with_context(|| format!("Failed to connect to Postgres at {pg_conn}"))?;

    // Drive the connection task; aborting it on a connection error is
    // fine because we only need it for the one query below.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            warn!("Postgres connection task ended: {e}");
        }
    });

    let row = client
        .query_one(
            "SELECT pgsleuth_wal_device()::text, pgsleuth_postmaster_pid()",
            &[],
        )
        .await
        .context("pgsleuth_wal_device() / pgsleuth_postmaster_pid() query failed")?;

    let wal_device: String = row.get(0);
    let postmaster_pid: i32 = row.get(1);
    info!("pg-ext discovery: wal_device={wal_device} postmaster_pid={postmaster_pid}");
    Ok(PgDiscovery { postmaster_pid })
}

/// Decide the effective PID filter given the CLI args and the pg-ext
/// discovery result. Behaviour:
///
/// - `--pid` always wins.
/// - If `--cgroup-id` is set, do not auto-fill a PID — the user picked
///   cgroup-based filtering on purpose.
/// - Otherwise, default to the postmaster PID from pg-ext.
///
/// Returns the PID to write into `FILTER_CONFIG.pid`, or `None` for "do
/// not filter by PID."
fn resolve_pid_filter(
    explicit_pid: Option<u32>,
    explicit_cgroup_id: Option<u64>,
    discovery: Option<&PgDiscovery>,
) -> Option<u32> {
    if let Some(pid) = explicit_pid {
        return Some(pid);
    }
    if explicit_cgroup_id.is_some() {
        return None;
    }
    discovery.and_then(|d| u32::try_from(d.postmaster_pid).ok())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    // pg-ext discovery: required for the auto-PID default, but optional
    // overall. Empty `--pg-conn` or a connection/query failure logs and
    // falls back to the explicit-flags-only path so the loader still
    // works on a Postgres without the extension installed.
    let discovery = if args.pg_conn.is_empty() {
        info!("--pg-conn is empty; skipping pg-ext discovery");
        None
    } else {
        match discover_via_pg_ext(&args.pg_conn).await {
            Ok(d) => Some(d),
            Err(e) => {
                warn!("pg-ext discovery failed; continuing without it: {e:#}");
                None
            }
        }
    };

    let effective_pid = resolve_pid_filter(args.pid, args.cgroup_id, discovery.as_ref());

    info!("Loading BPF object from: {}", args.bpf_object);
    let mut bpf = Ebpf::load_file(&args.bpf_object).context("Failed to load BPF object")?;

    let mut filter_config_map: Array<_, FilterConfig> = Array::try_from(
        bpf.map_mut("FILTER_CONFIG")
            .context("Failed to get FILTER_CONFIG map")?,
    )
    .context("Failed to convert map to Array")?;

    let mut config = FilterConfig {
        pid: effective_pid.unwrap_or(0),
        cgroup_id: args.cgroup_id.unwrap_or(0),
        name: [0u8; 16],
    };

    if !args.name.is_empty() {
        let src_bytes = args.name.as_bytes();
        let len = src_bytes.len().min(15);
        config.name[..len].copy_from_slice(&src_bytes[..len]);
    }

    filter_config_map
        .set(0, config, 0)
        .context("Failed to set filter config in map")?;

    match (effective_pid, args.pid, discovery.as_ref()) {
        (Some(pid), Some(_), _) => info!("Filtering for PID: {pid} (explicit --pid)"),
        (Some(pid), None, Some(_)) => {
            info!("Filtering for PID: {pid} (default — postmaster from pg-ext)");
        }
        (Some(pid), None, None) => info!("Filtering for PID: {pid}"),
        (None, _, _) => {}
    }
    if let Some(cgid) = args.cgroup_id {
        info!("Filtering for Cgroup ID: {cgid}");
    }
    if !args.name.is_empty() {
        info!("Filtering for process name: '{}'", args.name);
    }

    let program: &mut KProbe = bpf
        .program_mut("pgsleuth_ebpf")
        .unwrap()
        .try_into()
        .context("Failed to get program as KProbe")?;

    program.load().context("Failed to load BPF program")?;

    let _link = program
        .attach("vfs_open", 0)
        .context("Failed to attach kprobe to vfs_open")?;

    info!("Successfully attached kprobe to vfs_open");

    let events_map = RingBuf::try_from(bpf.take_map("EVENTS").context("Failed to get EVENTS map")?)
        .context("Failed to convert EVENTS map to RingBuf")?;

    let mut async_fd = AsyncFd::new(events_map).context("Failed to create AsyncFd")?;

    info!("Listening for file open events...");
    info!("Press Ctrl+C to stop.");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Exiting...");
                break;
            }
            res = async_fd.readable_mut() => {
                let mut guard = res.context("Failed to poll ring buffer")?;
                let rb = guard.get_inner_mut();

                while let Some(event_item) = rb.next() {
                    let event = unsafe { &*(event_item.as_ptr() as *const TraceEvent) };
                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("unknown")
                        .trim_matches(char::from(0));

                    info!("Activity Detected! PID={}, Comm='{}'", event.pid, comm);
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovery(pid: i32) -> PgDiscovery {
        PgDiscovery {
            postmaster_pid: pid,
        }
    }

    #[test]
    fn explicit_pid_wins_over_discovery() {
        let d = discovery(42);
        assert_eq!(resolve_pid_filter(Some(7), None, Some(&d)), Some(7));
    }

    #[test]
    fn cgroup_id_suppresses_auto_pid() {
        let d = discovery(42);
        assert_eq!(resolve_pid_filter(None, Some(99), Some(&d)), None);
    }

    #[test]
    fn discovery_pid_used_when_no_flags() {
        let d = discovery(42);
        assert_eq!(resolve_pid_filter(None, None, Some(&d)), Some(42));
    }

    #[test]
    fn no_filter_without_discovery_or_flags() {
        assert_eq!(resolve_pid_filter(None, None, None), None);
    }

    #[test]
    fn negative_postmaster_pid_is_rejected() {
        // Defensive: pgsleuth_postmaster_pid() returns int4 (signed) per
        // the pgrx definition. Negative values are nonsensical here; the
        // resolver must not coerce them to a u32 via `as`.
        let d = discovery(-1);
        assert_eq!(resolve_pid_filter(None, None, Some(&d)), None);
    }
}
