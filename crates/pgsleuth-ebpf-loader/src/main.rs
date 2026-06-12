// Userspace loader for pgsleuth eBPF POC.
//
// Attaches three programs: a vfs_open kprobe (the original skeleton
// path) and the block:block_rq_issue / block_rq_complete tracepoint
// pair (#18 + #43). The completion tracepoint emits per-IO latency
// events which this loader buckets into an OTel histogram and feeds
// to an inline v0 rule that fires the fsync-jitter Finding when P50
// latency on WAL-device write/flush operations breaches a threshold
// for N consecutive intervals.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::{
    maps::{Array, RingBuf},
    programs::{KProbe, TracePoint},
    Ebpf,
};
use chrono::Utc;
use clap::Parser;
use log::{info, warn};
use pgsleuth_core::{
    AttributeValue, BreachState, ConsecutiveBreachCounter, Finding, PgInstanceRef, PgRole,
    Remediation, Severity, Tier, FINDING_SCHEMA_VERSION,
};
use pgsleuth_ebpf_common::{BlockEvent, BlockIoLatencyEvent, FilterConfig, OpClass, TraceEvent};
use pgsleuth_otel::{Emitter, EmitterConfig, MetricsEmitter};
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tokio::time::{interval, MissedTickBehavior};

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

    /// OTLP/gRPC endpoint for emitting `pgsleuth.wal.io.latency`
    /// histogram metrics and Finding log records. Empty string disables
    /// OTel emission entirely (useful for development environments
    /// without a collector).
    #[arg(long, default_value = "")]
    otlp_endpoint: String,

    /// Identifier of this Postgres instance, written into the `Finding`
    /// when the fsync-jitter rule fires.
    #[arg(long, default_value = "fixture-pg")]
    pg_instance: String,

    /// Fsync-jitter rule threshold: per-interval P50 latency on the WAL
    /// device above this value counts as a breach (ms).
    #[arg(long, default_value_t = 10)]
    fsync_threshold_ms: u64,

    /// Fsync-jitter rule: emit a Finding after this many consecutive
    /// breaching intervals.
    #[arg(long, default_value_t = 3)]
    fsync_fire_after: u32,

    /// Length of each rule-evaluation interval in milliseconds.
    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,
}

/// Result of the startup pg-ext query.
struct PgDiscovery {
    /// Output of `pgsleuth_postmaster_pid()` — the PID of the Postgres
    /// supervisor process. Used as the default PID filter.
    postmaster_pid: i32,
    /// `pgsleuth_wal_device()` formatted as kernel-encoded `dev_t`:
    /// `(major << 20) | minor`.
    wal_dev_t: Option<u32>,
}

async fn discover_via_pg_ext(pg_conn: &str) -> Result<PgDiscovery> {
    info!("Connecting to Postgres via: {pg_conn}");
    let (client, connection) = tokio_postgres::connect(pg_conn, tokio_postgres::NoTls)
        .await
        .with_context(|| format!("Failed to connect to Postgres at {pg_conn}"))?;
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
/// `(major << 20) | minor`. Differs from glibc's `makedev`.
fn parse_kernel_dev_t(s: &str) -> Option<u32> {
    let (major_s, minor_s) = s.split_once(':')?;
    let major: u32 = major_s.trim().parse().ok()?;
    let minor: u32 = minor_s.trim().parse().ok()?;
    if major >= (1 << 12) || minor >= (1 << 20) {
        return None;
    }
    Some((major << 20) | minor)
}

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

fn op_class_str(op_class: u8) -> &'static str {
    match op_class {
        x if x == OpClass::Read as u8 => "read",
        x if x == OpClass::Write as u8 => "write",
        x if x == OpClass::WriteFlush as u8 => "write_flush",
        _ => "other",
    }
}

/// Compute the P50 of a slice of nanosecond latencies. Returns `None`
/// for empty input. Sorts a copy in-place; for 1-second windows on a
/// reasonable WAL workload the sample count is in the hundreds — well
/// under the threshold where we'd reach for an online estimator.
fn p50_ns(samples: &[u64]) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let mut v = samples.to_vec();
    v.sort_unstable();
    Some(v[v.len() / 2])
}

/// Build the Finding emitted when the fsync-jitter rule fires.
fn build_finding(
    pg_instance: &str,
    dev_label: &str,
    p50_ms: u64,
    threshold_ms: u64,
    streak: u32,
    interval_ms: u64,
) -> Finding {
    let mut otel_attributes = BTreeMap::new();
    otel_attributes.insert(
        "pgsleuth.wal.device".to_string(),
        AttributeValue::String(dev_label.to_string()),
    );
    Finding {
        schema_version: FINDING_SCHEMA_VERSION,
        rule_id: "storage.wal.fsync.jitter".to_string(),
        rule_version: 1,
        tier: Tier::Deep,
        severity: Severity::High,
        fired_at: Utc::now(),
        pg_instance: PgInstanceRef {
            id: pg_instance.to_string(),
            db_name: None,
            role: PgRole::Unknown,
        },
        summary: format!(
            "WAL device commit P50 latency {p50_ms}ms > {threshold_ms}ms for {streak} \
             consecutive {interval_ms}ms intervals (device={dev_label})"
        ),
        evidence: serde_json::json!({
            "p50_ms": p50_ms,
            "threshold_ms": threshold_ms,
            "streak_intervals": streak,
            "interval_ms": interval_ms,
            "device": dev_label,
        }),
        remediation: Remediation {
            text: "Investigate WAL device contention; check device IO queue depth and storage \
                   tail latency."
                .to_string(),
            knobs: vec![
                "wal_sync_method".to_string(),
                "synchronous_commit".to_string(),
            ],
        },
        otel_attributes,
    }
}

/// Per-interval accumulator of WAL-device write+flush latency samples
/// and the rule state. Updated by the event-drain loop, flushed by
/// the periodic tick.
struct RuleState {
    write_flush_samples_ns: Vec<u64>,
    counter: ConsecutiveBreachCounter,
}

impl RuleState {
    fn new() -> Self {
        Self {
            write_flush_samples_ns: Vec::with_capacity(2048),
            counter: ConsecutiveBreachCounter::default(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    // --- pg-ext discovery (best-effort) ---------------------------------
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
    let dev_label = format!("dev_t={effective_dev_t}");

    // --- OTel pipelines (best-effort) -----------------------------------
    let (log_emitter, metrics_emitter) = if args.otlp_endpoint.is_empty() {
        info!("--otlp-endpoint empty; OTel emission disabled (rule findings still logged)");
        (None, None)
    } else {
        let cfg = EmitterConfig {
            otlp_endpoint: args.otlp_endpoint.clone(),
            service_name: "pgsleuth-agent".to_string(),
            resource_attributes: BTreeMap::new(),
        };
        let log_em = match Emitter::try_new(&cfg) {
            Ok(e) => Some(e),
            Err(e) => {
                warn!("OTel log Emitter init failed; continuing without it: {e:#}");
                None
            }
        };
        let met_em = match MetricsEmitter::try_new(&cfg) {
            Ok(e) => Some(e),
            Err(e) => {
                warn!("OTel MetricsEmitter init failed; continuing without it: {e:#}");
                None
            }
        };
        (log_em, met_em)
    };

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

    log_filter_state(effective_pid, &args, discovery.as_ref(), effective_dev_t);

    // --- attach programs -----------------------------------------------
    attach_kprobe(&mut bpf)?;
    attach_block_issue(&mut bpf)?;
    attach_block_complete(&mut bpf)?;

    let events_map = RingBuf::try_from(bpf.take_map("EVENTS").context("Failed to get EVENTS map")?)
        .context("Failed to convert EVENTS map to RingBuf")?;
    let block_events_map = RingBuf::try_from(
        bpf.take_map("BLOCK_EVENTS")
            .context("Failed to get BLOCK_EVENTS map")?,
    )
    .context("Failed to convert BLOCK_EVENTS map to RingBuf")?;
    let latency_events_map = RingBuf::try_from(
        bpf.take_map("LATENCY_EVENTS")
            .context("Failed to get LATENCY_EVENTS map")?,
    )
    .context("Failed to convert LATENCY_EVENTS map to RingBuf")?;

    let mut events_fd = AsyncFd::new(events_map).context("Failed to create AsyncFd for EVENTS")?;
    let mut block_fd =
        AsyncFd::new(block_events_map).context("Failed to create AsyncFd for BLOCK_EVENTS")?;
    let mut latency_fd =
        AsyncFd::new(latency_events_map).context("Failed to create AsyncFd for LATENCY_EVENTS")?;

    info!(
        "Rule: storage.wal.fsync.jitter — P50 > {} ms for {} consecutive {} ms intervals",
        args.fsync_threshold_ms, args.fsync_fire_after, args.interval_ms
    );
    info!("Listening for events; Ctrl+C to stop.");

    let mut rule_state = RuleState::new();
    let mut tick = interval(Duration::from_millis(args.interval_ms));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // tokio::time::interval fires immediately on the first poll — skip it.
    tick.tick().await;

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
            res = latency_fd.readable_mut() => {
                let mut guard = res.context("Failed to poll LATENCY_EVENTS ring buffer")?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let event = unsafe { &*(item.as_ptr() as *const BlockIoLatencyEvent) };
                    let op = op_class_str(event.op_class);
                    if let Some(m) = metrics_emitter.as_ref() {
                        m.record_wal_io_latency(event.latency_ns, &dev_label, op);
                    }
                    if event.op_class == OpClass::Write as u8
                        || event.op_class == OpClass::WriteFlush as u8
                    {
                        rule_state.write_flush_samples_ns.push(event.latency_ns);
                    }
                }
                guard.clear_ready();
            }
            _ = tick.tick() => {
                let p50_ns_opt = p50_ns(&rule_state.write_flush_samples_ns);
                let p50_ns_val = p50_ns_opt.unwrap_or(0);
                // Display p50 in microseconds so sub-ms latencies are
                // visible at a glance; the threshold comparison is done
                // in nanoseconds to avoid integer-truncation losing
                // signal on overlay filesystems where everything is
                // fast.
                let p50_us = p50_ns_val / 1_000;
                let p50_ms = p50_ns_val / 1_000_000;
                let n = rule_state.write_flush_samples_ns.len();
                rule_state.write_flush_samples_ns.clear();

                let threshold_ns = args.fsync_threshold_ms.saturating_mul(1_000_000);
                let breached = p50_ns_opt
                    .map(|ns| ns > threshold_ns)
                    .unwrap_or(false);
                let state = rule_state.counter.observe(breached, args.fsync_fire_after);
                info!(
                    "[rule.tick] samples={n} p50_us={p50_us} p50_ms={p50_ms} \
                     breached={breached} state={state:?}"
                );

                if let BreachState::JustFired { streak } = state {
                    let finding = build_finding(
                        &args.pg_instance,
                        &dev_label,
                        p50_ms,
                        args.fsync_threshold_ms,
                        streak,
                        args.interval_ms,
                    );
                    if let Some(em) = log_emitter.as_ref() {
                        em.emit(&finding);
                    }
                    info!("FINDING fired: {}", finding.summary);
                }
            }
        }
    }

    if let Some(m) = metrics_emitter {
        m.shutdown();
    }
    if let Some(l) = log_emitter {
        l.shutdown();
    }
    Ok(())
}

fn log_filter_state(
    effective_pid: Option<u32>,
    args: &Args,
    discovery: Option<&PgDiscovery>,
    effective_dev_t: u32,
) {
    match (effective_pid, args.pid, discovery) {
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
        discovery.and_then(|d| d.wal_dev_t),
    ) {
        (0, _, _) => info!("dev_t filter off; block tracepoint will report ALL block I/O"),
        (d, Some(_), _) => info!("Filtering block-layer events for dev_t={d} (explicit --dev-t)"),
        (d, None, Some(_)) => {
            info!("Filtering block-layer events for dev_t={d} (kernel-encoded; from pg-ext)");
        }
        (d, None, None) => info!("Filtering block-layer events for dev_t={d}"),
    }
}

fn attach_kprobe(bpf: &mut Ebpf) -> Result<()> {
    let kprobe: &mut KProbe = bpf
        .program_mut("pgsleuth_ebpf")
        .context("Failed to get pgsleuth_ebpf program")?
        .try_into()
        .context("Failed to coerce program to KProbe")?;
    kprobe.load().context("Failed to load kprobe")?;
    // We deliberately leak the link by storing nothing — aya keeps it
    // alive for the lifetime of the program slot inside `bpf`, which
    // outlives main().
    kprobe
        .attach("vfs_open", 0)
        .context("Failed to attach kprobe to vfs_open")?;
    info!("Successfully attached kprobe to vfs_open");
    Ok(())
}

fn attach_block_issue(bpf: &mut Ebpf) -> Result<()> {
    let tp: &mut TracePoint = bpf
        .program_mut("pgsleuth_block_rq_issue")
        .context("Failed to get pgsleuth_block_rq_issue program")?
        .try_into()
        .context("Failed to coerce program to TracePoint")?;
    tp.load()
        .context("Failed to load block_rq_issue tracepoint program")?;
    tp.attach("block", "block_rq_issue")
        .context("Failed to attach tracepoint block:block_rq_issue")?;
    info!("Successfully attached tracepoint block:block_rq_issue");
    Ok(())
}

fn attach_block_complete(bpf: &mut Ebpf) -> Result<()> {
    let tp: &mut TracePoint = bpf
        .program_mut("pgsleuth_block_rq_complete")
        .context("Failed to get pgsleuth_block_rq_complete program")?
        .try_into()
        .context("Failed to coerce program to TracePoint")?;
    tp.load()
        .context("Failed to load block_rq_complete tracepoint program")?;
    tp.attach("block", "block_rq_complete")
        .context("Failed to attach tracepoint block:block_rq_complete")?;
    info!("Successfully attached tracepoint block:block_rq_complete");
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
        assert_eq!(parse_kernel_dev_t("254:1"), Some(0x0FE0_0001));
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
        assert_eq!(parse_kernel_dev_t("4096:0"), None);
        assert_eq!(parse_kernel_dev_t("0:1048576"), None);
    }

    #[test]
    fn op_class_str_covers_all_known_variants() {
        assert_eq!(op_class_str(OpClass::Read as u8), "read");
        assert_eq!(op_class_str(OpClass::Write as u8), "write");
        assert_eq!(op_class_str(OpClass::WriteFlush as u8), "write_flush");
        assert_eq!(op_class_str(OpClass::Other as u8), "other");
        assert_eq!(op_class_str(99), "other");
    }

    #[test]
    fn p50_of_empty_is_none() {
        assert_eq!(p50_ns(&[]), None);
    }

    #[test]
    fn p50_of_odd_count_is_middle() {
        assert_eq!(p50_ns(&[1, 5, 3, 9, 2]), Some(3));
    }

    #[test]
    fn p50_of_even_count_returns_upper_middle() {
        // We chose the simple "index = len/2" rule (no averaging). This
        // test pins it so a future change is intentional.
        assert_eq!(p50_ns(&[1, 2, 3, 4]), Some(3));
    }

    #[test]
    fn build_finding_carries_evidence_and_attrs() {
        let f = build_finding("prod-pg", "dev_t=266338304", 42, 10, 4, 1000);
        assert_eq!(f.rule_id, "storage.wal.fsync.jitter");
        assert!(matches!(f.tier, Tier::Deep));
        assert!(matches!(f.severity, Severity::High));
        assert_eq!(f.pg_instance.id, "prod-pg");
        assert_eq!(
            f.otel_attributes
                .get("pgsleuth.wal.device")
                .and_then(|v| match v {
                    AttributeValue::String(s) => Some(s.as_str()),
                    _ => None,
                }),
            Some("dev_t=266338304")
        );
        assert_eq!(f.evidence["p50_ms"], 42);
        assert_eq!(f.evidence["streak_intervals"], 4);
    }
}
