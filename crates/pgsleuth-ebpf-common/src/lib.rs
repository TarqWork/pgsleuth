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
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FilterConfig {}
