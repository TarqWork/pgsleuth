// Userspace loader for pgsleuth eBPF POC
// Loads kprobe + block tracepoint, fans out ring buffer events.

use anyhow::{Context, Result};
use aya::{
    maps::{Array, RingBuf},
    programs::{KProbe, TracePoint},
    Ebpf,
};
use clap::Parser;
use log::{info, warn};
use pgsleuth_ebpf_common::{BlockEvent, FilterConfig, TraceEvent};
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
    /// passed explicitly; the WAL device is used as the dev_t filter on
    /// the block-layer tracepoint. Pass `--pg-conn ''` (empty string) to
    /// skip the query — useful when the extension is not installed.
    #[arg(long, default_value = "postgres://postgres@localhost/postgres")]
    pg_conn: String,

    /// Kernel-encoded `dev_t` (`(major << 20) | minor`) override for the
    /// block-layer tracepoint filter. When set, takes priority over the
    /// value derived from `pgsleuth_wal_device()`. Useful when the
    /// stat-derived dev_t doesn't match the underlying block device the
    /// kernel reports (e.g. Docker overlay filesystems hide the real
    /// block device behind a synthetic st_dev). 0 means "no filter".
    #[arg(long)]
    dev_t: Option<u32>,
}

/// Result of the startup pg-ext query.
struct PgDiscovery {
    /// Output of `pgsleuth_postmaster_pid()` — the PID of the Postgres
    /// supervisor process. Used as the default PID filter.
    postmaster_pid: i32,
    /// `pgsleuth_wal_device()` formatted as kernel-encoded `dev_t`:
    /// `(major << 20) | minor`. The kernel's block tracepoint format
    /// uses this 20:12 split, **not** glibc's makedev encoding.
    wal_dev_t: Option<u32>,
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
    let wal_dev_t = parse_kernel_dev_t(&wal_device);
    if wal_dev_t.is_none() {
        warn!(
            "pg-ext discovery: could not parse wal_device={wal_device:?} as 'major:minor'; \
             dev_t filter will be disabled"
        );
    }
    info!(
        "pg-ext discovery: wal_device={wal_device} postmaster_pid={postmaster_pid} \
         kernel_dev_t={wal_dev_t:?}"
    );
    Ok(PgDiscovery {
        postmaster_pid,
        wal_dev_t,
    })
}

/// Parse `"major:minor"` into the **kernel** encoding of `dev_t`:
/// `(major << 20) | minor`. This intentionally differs from glibc's
/// `makedev` — the kernel's block-tracepoint `dev_t` field uses the
/// 20:12 split.
fn parse_kernel_dev_t(s: &str) -> Option<u32> {
    let (major_s, minor_s) = s.split_once(':')?;
    let major: u32 = major_s.trim().parse().ok()?;
    let minor: u32 = minor_s.trim().parse().ok()?;
    // 12-bit major, 20-bit minor inside a single u32; if either field
    // overflows we bail rather than silently truncating.
    if major >= (1 << 12) || minor >= (1 << 20) {
        return None;
    }
    Some((major << 20) | minor)
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

    // pg-ext discovery: required for the auto-PID + dev_t defaults, but
    // optional overall. Empty `--pg-conn` or a connection/query failure
    // logs and falls back to the explicit-flags-only path so the loader
    // still works on a Postgres without the extension installed.
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
    let effective_dev_t = args
        .dev_t
        .or_else(|| discovery.as_ref().and_then(|d| d.wal_dev_t))
        .unwrap_or(0);

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
        dev_t: effective_dev_t,
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
    match (
        effective_dev_t,
        args.dev_t,
        discovery.as_ref().and_then(|d| d.wal_dev_t),
    ) {
        (0, _, _) => info!("dev_t filter off; block tracepoint will report ALL block I/O"),
        (d, Some(_), _) => info!("Filtering block-layer events for dev_t={d} (explicit --dev-t)"),
        (d, None, Some(_)) => {
            info!("Filtering block-layer events for dev_t={d} (kernel-encoded; from pg-ext)");
        }
        (d, None, None) => info!("Filtering block-layer events for dev_t={d}"),
    }

    // --- vfs_open kprobe (existing skeleton path) -----------------------
    let kprobe: &mut KProbe = bpf
        .program_mut("pgsleuth_ebpf")
        .unwrap()
        .try_into()
        .context("Failed to get program as KProbe")?;
    kprobe.load().context("Failed to load kprobe")?;
    let _kprobe_link = kprobe
        .attach("vfs_open", 0)
        .context("Failed to attach kprobe to vfs_open")?;
    info!("Successfully attached kprobe to vfs_open");

    // --- block:block_rq_issue tracepoint (#18) --------------------------
    let block_tp: &mut TracePoint = bpf
        .program_mut("pgsleuth_block_rq_issue")
        .context("Failed to get pgsleuth_block_rq_issue program")?
        .try_into()
        .context("Failed to coerce program to TracePoint")?;
    block_tp
        .load()
        .context("Failed to load block_rq_issue tracepoint program")?;
    let _block_tp_link = block_tp
        .attach("block", "block_rq_issue")
        .context("Failed to attach tracepoint block:block_rq_issue")?;
    info!("Successfully attached tracepoint block:block_rq_issue");

    // --- ring buffer fan-out --------------------------------------------
    let events_map = RingBuf::try_from(bpf.take_map("EVENTS").context("Failed to get EVENTS map")?)
        .context("Failed to convert EVENTS map to RingBuf")?;
    let block_events_map = RingBuf::try_from(
        bpf.take_map("BLOCK_EVENTS")
            .context("Failed to get BLOCK_EVENTS map")?,
    )
    .context("Failed to convert BLOCK_EVENTS map to RingBuf")?;

    let mut events_fd = AsyncFd::new(events_map).context("Failed to create AsyncFd for EVENTS")?;
    let mut block_fd =
        AsyncFd::new(block_events_map).context("Failed to create AsyncFd for BLOCK_EVENTS")?;

    info!("Listening for events; Ctrl+C to stop.");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Exiting...");
                break;
            }
            res = events_fd.readable_mut() => {
                let mut guard = res.context("Failed to poll EVENTS ring buffer")?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let event = unsafe { &*(item.as_ptr() as *const TraceEvent) };
                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("unknown")
                        .trim_matches(char::from(0));
                    info!("Activity Detected! PID={}, Comm='{}'", event.pid, comm);
                }
                guard.clear_ready();
            }
            res = block_fd.readable_mut() => {
                let mut guard = res.context("Failed to poll BLOCK_EVENTS ring buffer")?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let event = unsafe { &*(item.as_ptr() as *const BlockEvent) };
                    let comm = std::str::from_utf8(&event.comm)
                        .unwrap_or("unknown")
                        .trim_matches(char::from(0));
                    info!(
                        "Block I/O on WAL dev! dev={} pid={} bytes={} comm='{}'",
                        event.dev, event.pid, event.bytes, comm
                    );
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
            wal_dev_t: None,
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
        let d = discovery(-1);
        assert_eq!(resolve_pid_filter(None, None, Some(&d)), None);
    }

    #[test]
    fn parses_kernel_dev_t_basic() {
        // 254:1 → (254 << 20) | 1 = 0x_FE0_0001 = 266338305.
        assert_eq!(parse_kernel_dev_t("254:1"), Some(0x_FE00001));
    }

    #[test]
    fn parses_kernel_dev_t_trims_whitespace() {
        assert_eq!(parse_kernel_dev_t("  8 : 16  "), Some((8 << 20) | 16));
    }

    #[test]
    fn rejects_bad_dev_t_strings() {
        assert_eq!(parse_kernel_dev_t(""), None);
        assert_eq!(parse_kernel_dev_t("254"), None);
        assert_eq!(parse_kernel_dev_t("a:b"), None);
        assert_eq!(parse_kernel_dev_t("254:1:0"), None);
    }

    #[test]
    fn rejects_dev_t_field_overflow() {
        // major field is 12 bits, minor is 20 bits.
        assert_eq!(parse_kernel_dev_t("4096:0"), None); // major == 2^12
        assert_eq!(parse_kernel_dev_t("0:1048576"), None); // minor == 2^20
    }
}
