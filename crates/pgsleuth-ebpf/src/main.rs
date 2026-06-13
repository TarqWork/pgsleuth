#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_ktime_get_ns,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::{ProbeContext, TracePointContext},
    EbpfContext,
};
use pgsleuth_ebpf_common::{
    BlockEvent, BlockIoLatencyEvent, FilterConfig, OpClass, RqKey, TempFileEvent, TraceEvent,
    FILE_EVENT_PATH_LEN,
};

// BPF map to store the filter configuration
#[map]
static mut FILTER_CONFIG: Array<FilterConfig> = Array::with_max_entries(1, 0);

// Ring buffer for the vfs_open kprobe (existing skeleton path).
#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1 << 12, 0);

// Ring buffer for block-layer events filtered by `dev_t` (#18).
#[map]
static mut BLOCK_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 12, 0);

// In-flight block I/O requests, keyed by (dev, sector). Inserted at
// `block_rq_issue`, looked up + deleted at `block_rq_complete`. The
// value is the issue timestamp in nanoseconds (`bpf_ktime_get_ns`).
//
// 8192 slots covers ~8k concurrent in-flight I/Os — far more than any
// realistic queue depth. A full map silently drops new issues, which
// is the safe failure mode (just missed latency samples).
#[map]
static mut INFLIGHT: HashMap<RqKey, u64> = HashMap::with_max_entries(8192, 0);

// Ring buffer for per-I/O latency events emitted by the
// `block_rq_complete` tracepoint after the issue lookup succeeds.
#[map]
static mut LATENCY_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 14, 0);

// Ring buffer for temp-file syscall events (#45).
#[map]
static mut TEMP_FILE_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 15, 0);

/// `sys_enter_openat` tracepoint format:
///   common header   offset 0..8
///   __syscall_nr    offset 8   size 4
///   dfd             offset 16  size 8 (long)
///   const char *fn  offset 24  size 8 (user pointer)
///   flags           offset 32  size 8
///   mode            offset 40  size 8
const OPENAT_OFF_FILENAME: usize = 24;
const UNLINKAT_OFF_FILENAME: usize = 24;

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
const BLOCK_RQ_OFF_SECTOR: usize = 16;
const BLOCK_RQ_ISSUE_OFF_BYTES: usize = 28;
const BLOCK_RQ_OFF_RWBS: usize = 32;

// `block:block_rq_complete` format differs only in that there's no
// `bytes` field — only `nr_sector` (offset 24) and `error` (28). We
// compute bytes from nr_sector * 512 on the completion side.
const BLOCK_RQ_COMPLETE_OFF_NR_SECTOR: usize = 24;
const SECTOR_SIZE_BYTES: u32 = 512;

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

/// Classify the `rwbs` flag string into [`OpClass`]. Looking only at the
/// first character + a scan for 'F'/'A' (FLUSH/FUA) covers the cases
/// the rule cares about — fsync writes get bucketed under
/// [`OpClass::WriteFlush`] regardless of whether the kernel reports
/// "WS" (sync), "WSM" (sync metadata), "FF" (flush+forceunit), …
fn classify_rwbs(rwbs: &[u8; 8]) -> u8 {
    let first = rwbs[0];
    let is_write = first == b'W' || first == b'F';
    let is_flush_or_fua = rwbs.iter().any(|&c| c == b'F' || c == b'A');
    if first == b'R' {
        OpClass::Read as u8
    } else if is_write && is_flush_or_fua {
        OpClass::WriteFlush as u8
    } else if is_write {
        OpClass::Write as u8
    } else {
        OpClass::Other as u8
    }
}

/// `block:block_rq_issue` tracepoint — fires when the block layer
/// issues an I/O request. Has two jobs:
///
/// 1. Record the issue timestamp in [`INFLIGHT`] keyed by `(dev,
///    sector)` so [`pgsleuth_block_rq_complete`] can compute latency.
/// 2. Emit a [`BlockEvent`] for the existing #18 skeleton path when
///    the operator wants per-event observation. Filtered by
///    `FilterConfig.dev_t` — 0 means "no filter, report all".
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
    let pass_dev_filter = config.dev_t == 0 || dev == config.dev_t;
    if !pass_dev_filter {
        return 0;
    }

    let sector: u64 = match unsafe { ctx.read_at::<u64>(BLOCK_RQ_OFF_SECTOR) } {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Record the issue time for latency correlation.
    let key = RqKey {
        dev,
        _pad: 0,
        sector,
    };
    let ts = unsafe { bpf_ktime_get_ns() };
    // Insert is best-effort: a full map drops the new entry silently
    // and we just miss this one I/O's latency sample. BPF_ANY = 0.
    let _ = unsafe { INFLIGHT.insert(&key, &ts, 0) };

    // Existing per-event surface for the #18 skeleton.
    let bytes: u32 = match unsafe { ctx.read_at::<u32>(BLOCK_RQ_ISSUE_OFF_BYTES) } {
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

/// `block:block_rq_complete` tracepoint — fires when the block layer
/// reports completion. Looks up the issue timestamp from [`INFLIGHT`]
/// (delete-on-read), computes latency, classifies the op via
/// `rwbs`, and emits a [`BlockIoLatencyEvent`]. Filtered by
/// `FilterConfig.dev_t`; an unknown `(dev, sector)` (no matching
/// issue) is silently dropped — happens when the program loads
/// mid-flight or under a HashMap collision.
#[tracepoint]
pub fn pgsleuth_block_rq_complete(ctx: TracePointContext) -> u32 {
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

    let sector: u64 = match unsafe { ctx.read_at::<u64>(BLOCK_RQ_OFF_SECTOR) } {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let key = RqKey {
        dev,
        _pad: 0,
        sector,
    };
    let issue_ts = unsafe {
        match INFLIGHT.get(&key) {
            Some(t) => *t,
            None => return 0,
        }
    };
    let _ = unsafe { INFLIGHT.remove(&key) };

    let now = unsafe { bpf_ktime_get_ns() };
    let latency_ns = now.saturating_sub(issue_ts);

    let nr_sector: u32 = match unsafe { ctx.read_at::<u32>(BLOCK_RQ_COMPLETE_OFF_NR_SECTOR) } {
        Ok(n) => n,
        Err(_) => 0,
    };
    let bytes = nr_sector.saturating_mul(SECTOR_SIZE_BYTES);

    let rwbs: [u8; 8] = match unsafe { ctx.read_at::<[u8; 8]>(BLOCK_RQ_OFF_RWBS) } {
        Ok(b) => b,
        Err(_) => [0u8; 8],
    };
    let op_class = classify_rwbs(&rwbs);

    if let Some(mut entry) = unsafe { LATENCY_EVENTS.reserve::<BlockIoLatencyEvent>(0) } {
        entry.write(BlockIoLatencyEvent {
            dev,
            op_class,
            _pad: [0u8; 3],
            bytes,
            latency_ns,
        });
        entry.submit(0);
    }

    0
}

/// `syscalls:sys_enter_openat` — fires on every `openat(2)` entry. We
/// filter by PID (from `FilterConfig.pid`); the userspace loader is
/// responsible for the path-substring filter ("contains `pgsql_tmp`")
/// because eBPF substring search is fragile. Volume on a real Postgres
/// is moderate; on the v0 fixture (single agent connection) it's tiny.
#[tracepoint]
pub fn pgsleuth_sys_enter_openat(ctx: TracePointContext) -> u32 {
    capture_file_syscall(&ctx, 0, OPENAT_OFF_FILENAME)
}

/// `syscalls:sys_enter_unlinkat` — fires on every `unlinkat(2)` entry.
/// Same filtering story as the openat probe.
#[tracepoint]
pub fn pgsleuth_sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    capture_file_syscall(&ctx, 1, UNLINKAT_OFF_FILENAME)
}

fn capture_file_syscall(ctx: &TracePointContext, syscall_kind: u8, off_filename: usize) -> u32 {
    let config = unsafe {
        match FILTER_CONFIG.get(0u32) {
            Some(c) => c,
            None => return 0,
        }
    };
    let current_pid = ctx.pid();
    if config.pid != 0 && current_pid != config.pid {
        return 0;
    }

    let filename_ptr: *const u8 = match unsafe { ctx.read_at::<*const u8>(off_filename) } {
        Ok(p) => p,
        Err(_) => return 0,
    };
    if filename_ptr.is_null() {
        return 0;
    }

    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        _ => [0u8; 16],
    };

    if let Some(mut entry) = unsafe { TEMP_FILE_EVENTS.reserve::<TempFileEvent>(0) } {
        let evt_ptr: *mut TempFileEvent = entry.as_mut_ptr().cast();
        unsafe {
            (*evt_ptr).pid = current_pid;
            (*evt_ptr).syscall = syscall_kind;
            (*evt_ptr)._pad = [0u8; 3];
            (*evt_ptr).bytes = 0;
            (*evt_ptr).query_hash = 0;
            (*evt_ptr).comm = comm;
            (*evt_ptr).path = [0u8; FILE_EVENT_PATH_LEN];
            // Read the user-space path string into the event payload.
            // Errors are best-effort — we still emit the event with an
            // empty path so the userspace dedup keeps PID telemetry.
            let path_slice: &mut [u8] = &mut (*evt_ptr).path;
            let _ = bpf_probe_read_user_str_bytes(filename_ptr, path_slice);
        }
        entry.submit(0);
    }

    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
