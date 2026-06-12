// Userspace loader for pgsleuth eBPF POC
// Loads kprobe and reads ring buffer events filtered by a configurable name.

use anyhow::{Context, Result};
use aya::{
    maps::{Array, RingBuf},
    programs::KProbe,
    Ebpf,
};
use clap::Parser;
use log::info;
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

    /// PID to filter for
    #[arg(long)]
    pid: Option<u32>,

    /// Cgroup ID to filter for
    #[arg(long)]
    cgroup_id: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("Loading BPF object from: {}", args.bpf_object);

    // Load the BPF program
    let mut bpf = Ebpf::load_file(&args.bpf_object).context("Failed to load BPF object")?;

    // Update filter config map
    let mut filter_config_map: Array<_, FilterConfig> = Array::try_from(
        bpf.map_mut("FILTER_CONFIG")
            .context("Failed to get FILTER_CONFIG map")?,
    )
    .context("Failed to convert map to Array")?;

    let mut config = FilterConfig {
        pid: args.pid.unwrap_or(0),
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

    if let Some(pid) = args.pid {
        info!("Filtering for PID: {}", pid);
    }
    if let Some(cgid) = args.cgroup_id {
        info!("Filtering for Cgroup ID: {}", cgid);
    }
    if !args.name.is_empty() {
        info!("Filtering for process name: '{}'", args.name);
    }

    // Load and attach the kprobe
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

    // Read events from ring buffer
    let events_map = RingBuf::try_from(bpf.take_map("EVENTS").context("Failed to get EVENTS map")?)
        .context("Failed to convert EVENTS map to RingBuf")?;

    let mut async_fd = AsyncFd::new(events_map).context("Failed to create AsyncFd")?;

    info!("Listening for file open events...");
    info!("Press Ctrl+C to stop.");

    // Poll ring buffer
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
