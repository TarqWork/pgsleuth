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
