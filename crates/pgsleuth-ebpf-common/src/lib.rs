#![cfg_attr(not(feature = "user"), no_std)]

// Wire types shared between kernel-side eBPF and userspace loader.

use aya_ebpf_cty::c_long;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct SyscallEvent {
    pub pid: u32,
    pub syscall_nr: c_long,
    pub filename_ptr: u64,
}

/// Event sent from eBPF to userspace when a target activity is detected.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct TraceEvent {
    /// PID of the process that triggered the event
    pub pid: u32,
    /// Port number detected (0 if unknown, 5432 for Postgres)
    pub port: u32,
    /// Null‑terminated process name (comm) of the task (max 16 bytes)
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TraceEvent {}

/// Filter configuration for the eBPF program.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct FilterConfig {
    /// PID to filter for (0 to ignore)
    pub pid: u32,
    /// Cgroup ID to filter for (0 to ignore)
    pub cgroup_id: u64,
    /// Process name to filter for (empty string to ignore)
    pub name: [u8; 16],
    /// Kernel-encoded `dev_t` (`(major << 20) | minor`) of the block
    /// device the block-layer tracepoint should observe. 0 disables the
    /// dev_t filter. NOT the glibc encoding — the loader does the
    /// conversion from `pgsleuth_wal_device()`'s `"major:minor"` string.
    pub dev_t: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FilterConfig {}

/// Event sent from the block-layer tracepoint to userspace when an I/O
/// request is issued against the filtered `dev_t`.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct BlockEvent {
    /// Kernel-encoded `dev_t` of the device the I/O hit.
    pub dev: u32,
    /// PID that issued the I/O.
    pub pid: u32,
    /// Number of bytes in the request.
    pub bytes: u32,
    /// `comm` of the issuing task.
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockEvent {}

/// Coarse classification of a block I/O request's operation. The
/// kernel's `rwbs` field on block tracepoints is an 8-byte string of
/// flag letters (R/W/F/FUA/SYNC/M/D); we squash it into a small enum
/// so the histogram label space stays bounded.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OpClass {
    /// Read.
    Read = 0,
    /// Write.
    Write = 1,
    /// Write + FLUSH or FUA (the fsync path).
    WriteFlush = 2,
    /// Anything else (discard, metadata, …).
    Other = 3,
}

/// Pair `(dev_t, sector)` that uniquely identifies an in-flight block
/// I/O request between `block_rq_issue` and `block_rq_complete`. Used
/// as the BPF `HashMap` key in [`super::pgsleuth_ebpf`]; the kernel
/// program inserts on issue and looks up + deletes on complete.
///
/// `(dev, sector)` is what BCC's `biolatency` uses for the same
/// purpose. Collisions are theoretically possible under tens of
/// millions of IOPS — far above any v0 target.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct RqKey {
    /// Kernel-encoded `dev_t`.
    pub dev: u32,
    /// Padding so the struct is `repr(C)`-aligned cleanly for BPF maps.
    pub _pad: u32,
    /// Starting sector of the request.
    pub sector: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RqKey {}

/// Per-I/O latency event emitted by `block_rq_complete` after looking
/// up the issue timestamp in the `INFLIGHT` map. Drives the userspace
/// histogram + the "commit latency > 10ms for >3 intervals" rule.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct BlockIoLatencyEvent {
    /// Kernel-encoded `dev_t`.
    pub dev: u32,
    /// Op classification (read / write / write+flush / other).
    pub op_class: u8,
    /// 3 bytes of explicit padding so the struct layout is portable.
    pub _pad: [u8; 3],
    /// Request size in bytes.
    pub bytes: u32,
    /// `block_rq_complete.ts_ns - block_rq_issue.ts_ns`.
    pub latency_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockIoLatencyEvent {}

/// Maximum bytes captured from the `openat`/`unlinkat` filename. 128 is
/// enough for any realistic `pgsql_tmp/...` path under `$PGDATA`.
pub const FILE_EVENT_PATH_LEN: usize = 128;

/// Event emitted by the `syscalls:sys_enter_openat` /
/// `sys_enter_unlinkat` tracepoints. Per-event userspace filter checks
/// whether `path` contains `pgsql_tmp` and emits a `Finding` if so.
/// v0 ships syscall tracepoints only; the `BufFileCreateTemp` uprobe
/// for byte-counting + query-hash attribution lands later — the event
/// shape leaves slots (`bytes`, `query_hash`) for those values to be
/// filled in without breaking the wire.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct TempFileEvent {
    /// PID of the backend that issued the syscall.
    pub pid: u32,
    /// Syscall kind: 0 = openat, 1 = unlinkat. Anything else reserved.
    pub syscall: u8,
    /// 3 bytes of padding so subsequent fields are u32-aligned.
    pub _pad: [u8; 3],
    /// Bytes written, or 0 when the uprobe attribution layer hasn't
    /// landed (v0). Future: filled in by `BufFileCreateTemp` /
    /// `BufFileWrite` uprobes.
    pub bytes: u64,
    /// Stable query hash, or 0 in v0. Future: filled in by the same
    /// uprobe layer that knows which backend is running which query.
    pub query_hash: u64,
    /// Process command (`comm`).
    pub comm: [u8; 16],
    /// Null-terminated path bytes read from the user pointer.
    pub path: [u8; FILE_EVENT_PATH_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TempFileEvent {}
