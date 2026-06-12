// Silences warnings from pgrx macros checking for multiple PG versions
#![allow(unexpected_cfgs)]

//! pgsleuth — Postgres-side helper functions for the pgsleuth eBPF
//! observability layer.
//!
//! v0 scope (skeleton): expose just enough state for the userspace
//! loader to bootstrap its filters at startup.
//!
//! - `pgsleuth_wal_device()` returns the `major:minor` of the device
//!   holding `$PGDATA/pg_wal`, so the loader can filter eBPF block-layer
//!   events to the WAL device.
//! - `pgsleuth_postmaster_pid()` returns the postmaster PID, so the
//!   loader can scope process-based filters without guessing.

use pgrx::prelude::*;

::pgrx::pg_module_magic!();

/// Returns the `"major:minor"` of the device holding `$PGDATA/pg_wal`.
///
/// The loader uses this to scope block-layer eBPF events to the WAL
/// device only, which is the primary signal for fsync-jitter detection
/// (alarm #3 in `pgsleuth/docs/research/Database Observability Alarms.md`).
#[pg_extern]
fn pgsleuth_wal_device() -> String {
    let data_dir = unsafe {
        // `DataDir` is a `*const c_char` pointing at the active data directory.
        std::ffi::CStr::from_ptr(pgrx::pg_sys::DataDir)
    }
    .to_string_lossy()
    .into_owned();

    let wal_path = format!("{data_dir}/pg_wal");
    let meta =
        std::fs::metadata(&wal_path).unwrap_or_else(|e| panic!("stat({wal_path}) failed: {e}"));

    use std::os::unix::fs::MetadataExt;
    let dev = meta.dev();
    let major = libc::major(dev);
    let minor = libc::minor(dev);
    format!("{major}:{minor}")
}

/// Returns the postmaster PID.
///
/// The loader uses this as the default root for PID/cgroup-based filters
/// when the operator does not pass `--pid` / `--cgroup-id` explicitly.
#[pg_extern]
fn pgsleuth_postmaster_pid() -> i32 {
    unsafe { pgrx::pg_sys::PostmasterPid as i32 }
}

// -----------------------------------------------------------------------------
// Tests — run via `cargo pgrx test`.
// -----------------------------------------------------------------------------

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    #[pg_test]
    fn test_wal_device_returns_major_minor() {
        let dev: String = Spi::get_one("SELECT pgsleuth_wal_device()")
            .expect("SPI call failed")
            .expect("NULL returned");
        assert!(
            dev.contains(':'),
            "expected 'major:minor' format, got {dev:?}"
        );
    }

    #[pg_test]
    fn test_wal_device_matches_stat_on_pgdata() {
        // Independent path: shell out to `stat -c '%d' $PGDATA/pg_wal`
        // and split the decimal st_dev into major:minor by hand. This
        // catches a libc::major/minor implementation drift or a wrong
        // DataDir read — the two paths share only the kernel's
        // stat(2) result.
        use std::process::Command;

        let data_dir: String = Spi::get_one("SHOW data_directory")
            .expect("SPI call failed")
            .expect("NULL returned");
        let wal_dir = format!("{data_dir}/pg_wal");

        let stat_out = Command::new("stat")
            .args(["-c", "%d", &wal_dir])
            .output()
            .unwrap_or_else(|e| panic!("stat invocation failed: {e}"));
        assert!(
            stat_out.status.success(),
            "stat exited non-zero: {}",
            String::from_utf8_lossy(&stat_out.stderr)
        );
        let st_dev: u64 = String::from_utf8_lossy(&stat_out.stdout)
            .trim()
            .parse()
            .expect("stat output was not a decimal number");

        // Linux MAJOR/MINOR for the 32-bit case (matches glibc's
        // sysmacros.h). Simple-case form covers normal block devices;
        // the OR-ed high bits cover the rare 64-bit dev_t.
        let expected_major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & !0xfff);
        let expected_minor = (st_dev & 0xff) | ((st_dev >> 12) & !0xff);
        let expected = format!("{expected_major}:{expected_minor}");

        let actual: String = Spi::get_one("SELECT pgsleuth_wal_device()")
            .expect("SPI call failed")
            .expect("NULL returned");

        assert_eq!(
            actual, expected,
            "pgsleuth_wal_device()='{actual}' disagrees with stat({wal_dir}) st_dev={st_dev} -> '{expected}'"
        );
    }

    #[pg_test]
    fn test_postmaster_pid_is_positive() {
        let pid: i32 = Spi::get_one("SELECT pgsleuth_postmaster_pid()")
            .expect("SPI call failed")
            .expect("NULL returned");
        assert!(pid > 0, "postmaster PID should be positive, got {pid}");
    }
}

#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {}
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        vec![]
    }
}
