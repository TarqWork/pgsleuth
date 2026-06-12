#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_comm},
    macros::{kprobe, map},
    maps::{Array, RingBuf},
    programs::ProbeContext,
    EbpfContext,
};
use pgsleuth_ebpf_common::{FilterConfig, TraceEvent};

// BPF map to store the filter configuration
#[map]
static mut FILTER_CONFIG: Array<FilterConfig> = Array::with_max_entries(1, 0);

// Ring buffer to send events to userspace
#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1 << 12, 0);

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
