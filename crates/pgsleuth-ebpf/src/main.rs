#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_comm},
    macros::{kprobe, map, tracepoint},
    maps::{Array, RingBuf},
    programs::{ProbeContext, TracePointContext},
    EbpfContext,
};
use pgsleuth_ebpf_common::{BlockEvent, FilterConfig, TraceEvent};

// BPF map to store the filter configuration
#[map]
static mut FILTER_CONFIG: Array<FilterConfig> = Array::with_max_entries(1, 0);

// Ring buffer for the vfs_open kprobe (existing skeleton path).
#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1 << 12, 0);

// Ring buffer for block-layer events filtered by `dev_t` (#18).
#[map]
static mut BLOCK_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 12, 0);

// `block:block_rq_issue` tracepoint format (kernel 5.x+):
//
//   common_type      offset:0  size:2
//   common_flags     offset:2  size:1
//   common_preempt   offset:3  size:1
//   common_pid       offset:4  size:4
//   dev_t dev        offset:8  size:4   <-- the field we filter on
//   sector_t sector  offset:16 size:8
//   nr_sector        offset:24 size:4
//   bytes            offset:28 size:4   <-- we report this in BlockEvent
//   rwbs[8]          offset:32 size:8
//   comm[16]         offset:40 size:16
//
// Offsets are stable kernel ABI per tracepoint format contract. If the
// kernel ever bumps the format we will see misreads; the loader logs
// the dev value it sees so a mismatch is visible.
const BLOCK_RQ_OFF_DEV: usize = 8;
const BLOCK_RQ_OFF_BYTES: usize = 28;

#[kprobe(function = "vfs_open")]
pub fn pgsleuth_ebpf(ctx: ProbeContext) -> u32 {
    let current_pid = ctx.pid();
    let current_cgid = unsafe { bpf_get_current_cgroup_id() };

    // Get filter config from map
    let config = unsafe {
        match FILTER_CONFIG.get(0u32) {
            Some(c) => c,
            None => return 1,
        }
    };

    let mut matches = false;
    let mut criteria_met = 0;

    // Filter by CGID if provided
    if config.cgroup_id != 0 {
        criteria_met += 1;
        if current_cgid == config.cgroup_id {
            matches = true;
        }
    }

    // Filter by PID if provided and CGID didn't already match
    if !matches && config.pid != 0 {
        criteria_met += 1;
        if current_pid == config.pid {
            matches = true;
        }
    }

    // Filter by Name if provided and nothing matched yet
    if !matches && config.name[0] != 0 {
        criteria_met += 1;
        // Get the process name (comm)
        let comm = match bpf_get_current_comm() {
            Ok(c) => c,
            _ => [0u8; 16],
        };

        let mut name_matches = true;
        for i in 0..16 {
            if config.name[i] == 0 {
                break;
            }
            if comm[i] != config.name[i] {
                name_matches = false;
                break;
            }
        }
        if name_matches {
            matches = true;
        }
    }

    // If no criteria were specified, or criteria were specified but didn't match
    if criteria_met > 0 && !matches {
        return 1;
    }

    // Get the process name (comm) for the event report
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        _ => [0u8; 16],
    };

    // Send event to userspace
    if let Some(mut entry) = unsafe { EVENTS.reserve::<TraceEvent>(0) } {
        entry.write(TraceEvent {
            pid: current_pid,
            port: 0,
            comm,
        });
        entry.submit(0);
    }

    0
}

/// `block:block_rq_issue` tracepoint — fires when the block layer
/// issues an I/O request. When `FilterConfig.dev_t` is non-zero, only
/// requests against that device are reported. When it's 0, all I/O is
/// reported — matches the convention used by the PID/cgroup/name
/// filters above.
#[tracepoint]
pub fn pgsleuth_block_rq_issue(ctx: TracePointContext) -> u32 {
    let config = unsafe {
        match FILTER_CONFIG.get(0u32) {
            Some(c) => c,
            None => return 0,
        }
    };

    let dev: u32 = match unsafe { ctx.read_at::<u32>(BLOCK_RQ_OFF_DEV) } {
        Ok(d) => d,
        Err(_) => return 0,
    };
    if config.dev_t != 0 && dev != config.dev_t {
        return 0;
    }

    let bytes: u32 = match unsafe { ctx.read_at::<u32>(BLOCK_RQ_OFF_BYTES) } {
        Ok(b) => b,
        Err(_) => 0,
    };

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        _ => [0u8; 16],
    };

    if let Some(mut entry) = unsafe { BLOCK_EVENTS.reserve::<BlockEvent>(0) } {
        entry.write(BlockEvent {
            dev,
            pid: ctx.pid(),
            bytes,
            comm,
        });
        entry.submit(0);
    }

    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
