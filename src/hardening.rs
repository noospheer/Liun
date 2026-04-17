//! # Process-level hardening
//!
//! OS-level knobs that reduce the blast radius of a compromise or crash.
//! These complement what the systemd unit does from the outside:
//!
//! | Concern | systemd unit provides | This module provides |
//! |---|---|---|
//! | Swap → disk leak | `MemorySwapMax=0` | (nothing — kernel-level is stronger) |
//! | Core dump → disk leak | `LimitCORE=0` if set | `PR_SET_DUMPABLE=0` via prctl |
//! | ptrace attach | `NoNewPrivileges=yes` helps | `PR_SET_DUMPABLE=0` also blocks ptrace |
//! | Kernel tunables / modules | `ProtectKernelModules=yes` etc | (out of scope) |
//!
//! For production, run with BOTH the systemd hardening AND this module.
//! Running this module without systemd is still useful — a bare-metal or
//! container-without-systemd deployment gets the in-process protections.

/// Disable core dumps and ptrace attachment for this process.
///
/// Sets `prctl(PR_SET_DUMPABLE, 0)` on Linux. Effects:
/// - No core dump will be written on SIGSEGV / SIGABRT / etc.
/// - `/proc/<pid>/mem` and ptrace attach are denied (even to same-uid
///   processes; root can still override).
/// - The process's `/proc/<pid>` entries owned by root, not the user.
///
/// Call at startup, before any secret material enters memory.
#[cfg(target_os = "linux")]
pub fn disable_core_dumps() -> Result<(), std::io::Error> {
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) has well-defined behavior and never
    // corrupts memory. Return is -1 on error.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn disable_core_dumps() -> Result<(), std::io::Error> {
    // No-op on non-Linux. macOS has similar via setrlimit(RLIMIT_CORE, 0),
    // but we don't officially support production macOS yet.
    Ok(())
}

/// Attempt to lock all current and future process memory in RAM so it
/// never swaps to disk. Requires `CAP_IPC_LOCK` capability (systemd unit
/// grants this via `AmbientCapabilities=CAP_IPC_LOCK`), or for the process
/// to be running as root, or for `RLIMIT_MEMLOCK` to be sufficient.
///
/// This is a belt-and-suspenders measure on top of `MemorySwapMax=0`
/// (which is enforced by the systemd unit at cgroup level).
#[cfg(target_os = "linux")]
pub fn mlock_all() -> Result<(), std::io::Error> {
    // SAFETY: mlockall with MCL_CURRENT | MCL_FUTURE has well-defined
    // semantics and does not corrupt memory.
    let rc = unsafe {
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE)
    };
    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn mlock_all() -> Result<(), std::io::Error> {
    Ok(())
}
