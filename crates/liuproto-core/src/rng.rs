//! # Random source with multi-backend hardware TRNG support
//!
//! Every random byte entering the system goes through this module. The
//! source is configured via a process-global mode set once at startup.
//!
//! ## Modes
//!
//! | Mode | Source | Security | Hardware |
//! |---|---|---|---|
//! | `urandom` | `getrandom` / `/dev/urandom` | Computational (CSPRNG) | Any |
//! | `rdseed` | Intel RDSEED instruction | Information-theoretic | Intel Broadwell+, AMD Zen+ |
//! | `rndr` | ARM RNDR instruction | Information-theoretic | ARMv8.5+ (Apple M1+, Graviton 3+) |
//! | `auto` | Best available TRNG, else urandom | Best available | Any |
//!
//! ## Refusal semantics
//!
//! Requesting a specific hardware mode (`rdseed`, `rndr`) when the CPU
//! doesn't support it fails with a clear error. **No silent fallback.**
//! `auto` mode detects and picks the best available without refusing.

use std::sync::atomic::{AtomicU8, Ordering};

/// Which random source `fill()` uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngMode {
    /// OS randomness (`getrandom` / `/dev/urandom`). CSPRNG, not ITS.
    Urandom,
    /// Hardware TRNG via Intel RDSEED instruction. ITS-suitable.
    Rdseed,
    /// Hardware TRNG via ARM RNDR instruction. ITS-suitable.
    Rndr,
    /// Software ITS entropy via `trandom` daemon (`/dev/trandom`).
    /// Multi-source noise + LHL extraction — no CSPRNG in the path.
    /// ITS-suitable on any x86 machine (including cloud VMs without
    /// RDSEED). Requires `trandomd` running. 1 KB/s–14 MB/s.
    Trandom,
}

impl RngMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Urandom => "urandom",
            Self::Rdseed => "rdseed",
            Self::Rndr => "rndr",
            Self::Trandom => "trandom",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "urandom" | "getrandom" | "csprng" => Some(Self::Urandom),
            "rdseed" | "hardware" => Some(Self::Rdseed),
            "rndr" | "arm-trng" => Some(Self::Rndr),
            "trandom" => Some(Self::Trandom),
            "auto" | "trng" => Some(detect_best()),
            _ => None,
        }
    }

    pub fn is_its(&self) -> bool {
        matches!(self, Self::Rdseed | Self::Rndr | Self::Trandom)
    }

    fn to_byte(self) -> u8 {
        match self {
            Self::Urandom => 0,
            Self::Rdseed => 1,
            Self::Rndr => 2,
            Self::Trandom => 3,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Urandom),
            1 => Some(Self::Rdseed),
            2 => Some(Self::Rndr),
            3 => Some(Self::Trandom),
            _ => None,
        }
    }
}

/// Detect the best available TRNG. Preference order:
/// RDSEED > RNDR > trandom > urandom.
pub fn detect_best() -> RngMode {
    if rdseed_available() {
        RngMode::Rdseed
    } else if rndr_available() {
        RngMode::Rndr
    } else if trandom_available() {
        RngMode::Trandom
    } else {
        RngMode::Urandom
    }
}

// Default = 255 (unset). Must be explicitly configured at startup.
// If still unset when fill() is called, panics with a clear message.
static GLOBAL_MODE: AtomicU8 = AtomicU8::new(255);

/// Set the process-global RNG mode. Call once at startup.
pub fn set_mode(mode: RngMode) -> Result<(), RngError> {
    match mode {
        RngMode::Rdseed if !rdseed_available() => {
            return Err(RngError::HardwareUnavailable("RDSEED"));
        }
        RngMode::Rndr if !rndr_available() => {
            return Err(RngError::HardwareUnavailable("RNDR"));
        }
        RngMode::Trandom if !trandom_available() => {
            return Err(RngError::TrandomUnavailable);
        }
        _ => {}
    }
    GLOBAL_MODE.store(mode.to_byte(), Ordering::SeqCst);
    Ok(())
}

/// The currently-configured RNG mode. If never explicitly set, auto-
/// detects on first call (picks best available ITS source, falls back
/// to urandom only if no TRNG exists).
pub fn current_mode() -> RngMode {
    let b = GLOBAL_MODE.load(Ordering::Relaxed);
    match RngMode::from_byte(b) {
        Some(m) => m,
        None => {
            // First call without explicit set_mode — auto-detect.
            let best = detect_best();
            // CAS: only one thread wins the init race.
            let _ = GLOBAL_MODE.compare_exchange(
                255, best.to_byte(), Ordering::SeqCst, Ordering::Relaxed,
            );
            RngMode::from_byte(GLOBAL_MODE.load(Ordering::Relaxed))
                .expect("RNG mode invariant broken")
        }
    }
}

/// Fill `buf` with random bytes from the configured source.
pub fn fill(buf: &mut [u8]) -> Result<(), RngError> {
    match current_mode() {
        RngMode::Urandom => getrandom::fill(buf).map_err(|e| RngError::Io(e.to_string())),
        RngMode::Rdseed => fill_rdseed(buf),
        RngMode::Rndr => fill_rndr(buf),
        RngMode::Trandom => fill_trandom(buf),
    }
}

/// Like `fill`, but panics on error.
pub fn fill_expect(buf: &mut [u8]) {
    fill(buf).expect("random source failed")
}

/// Check which hardware TRNGs are present on this CPU.
pub fn available_backends() -> Vec<RngMode> {
    let mut out = vec![RngMode::Urandom];
    if rdseed_available() { out.push(RngMode::Rdseed); }
    if rndr_available() { out.push(RngMode::Rndr); }
    if trandom_available() { out.push(RngMode::Trandom); }
    out
}

/// Errors from the RNG layer.
#[derive(Debug)]
pub enum RngError {
    Io(String),
    HardwareUnavailable(&'static str),
    HardwareExhausted(&'static str),
    /// trandom daemon not running or /dev/trandom not present.
    TrandomUnavailable,
}

impl std::fmt::Display for RngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "rng io error: {e}"),
            Self::HardwareUnavailable(name) =>
                write!(f, "{name} instruction unavailable on this CPU"),
            Self::HardwareExhausted(name) =>
                write!(f, "{name} retry budget exhausted — hardware DRNG may be faulty"),
            Self::TrandomUnavailable =>
                write!(f, "/dev/trandom not found — is trandomd running? \
                       Install: https://github.com/noospheer/trandom"),
        }
    }
}

impl std::error::Error for RngError {}

// ── RDSEED (x86_64) ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn rdseed_available() -> bool {
    std::arch::is_x86_feature_detected!("rdseed")
}

#[cfg(not(target_arch = "x86_64"))]
fn rdseed_available() -> bool { false }

#[cfg(target_arch = "x86_64")]
fn fill_rdseed(buf: &mut [u8]) -> Result<(), RngError> {
    if !rdseed_available() {
        return Err(RngError::HardwareUnavailable("RDSEED"));
    }
    unsafe { rdseed_impl(buf) }
}

#[cfg(not(target_arch = "x86_64"))]
fn fill_rdseed(_buf: &mut [u8]) -> Result<(), RngError> {
    Err(RngError::HardwareUnavailable("RDSEED"))
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "rdseed")]
unsafe fn rdseed_impl(buf: &mut [u8]) -> Result<(), RngError> {
    use std::arch::x86_64::_rdseed64_step;
    const MAX_RETRIES: u32 = 1000;
    let mut i = 0;
    while i < buf.len() {
        let mut val: u64 = 0;
        let mut retries = 0u32;
        while _rdseed64_step(&mut val) == 0 {
            retries += 1;
            if retries >= MAX_RETRIES {
                return Err(RngError::HardwareExhausted("RDSEED"));
            }
            std::hint::spin_loop();
        }
        let bytes = val.to_le_bytes();
        let take = (buf.len() - i).min(8);
        buf[i..i + take].copy_from_slice(&bytes[..take]);
        i += take;
    }
    Ok(())
}

// ── RNDR (aarch64) ────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
fn rndr_available() -> bool {
    // RNDR is mandatory in ARMv8.5+. Detect via auxiliary vector.
    // The HWCAP2_RNG bit (bit 16) signals FEAT_RNG.
    #[cfg(target_os = "linux")]
    {
        let hwcap2 = unsafe { libc::getauxval(libc::AT_HWCAP2) };
        hwcap2 & (1 << 16) != 0
    }
    #[cfg(target_os = "macos")]
    {
        // All Apple Silicon (M1+) supports RNDR.
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn rndr_available() -> bool { false }

#[cfg(target_arch = "aarch64")]
fn fill_rndr(buf: &mut [u8]) -> Result<(), RngError> {
    if !rndr_available() {
        return Err(RngError::HardwareUnavailable("RNDR"));
    }
    const MAX_RETRIES: u32 = 1000;
    let mut i = 0;
    while i < buf.len() {
        let mut val: u64;
        let mut retries = 0u32;
        loop {
            let ok: u64;
            unsafe {
                core::arch::asm!(
                    "mrs {val}, s3_3_c2_c4_0",  // RNDR register
                    "cset {ok}, ne",              // 1 if valid
                    val = out(reg) val,
                    ok = out(reg) ok,
                );
            }
            if ok != 0 { break; }
            retries += 1;
            if retries >= MAX_RETRIES {
                return Err(RngError::HardwareExhausted("RNDR"));
            }
            std::hint::spin_loop();
        }
        let bytes = val.to_le_bytes();
        let take = (buf.len() - i).min(8);
        buf[i..i + take].copy_from_slice(&bytes[..take]);
        i += take;
    }
    Ok(())
}

#[cfg(not(target_arch = "aarch64"))]
fn fill_rndr(_buf: &mut [u8]) -> Result<(), RngError> {
    Err(RngError::HardwareUnavailable("RNDR"))
}

// ── trandom (/dev/trandom character device) ───────────────────────────
//
// trandom (https://github.com/noospheer/trandom) is a userspace daemon
// that extracts ITS-quality entropy from multiple OS noise sources via
// CLMUL-GHASH + the Leftover Hash Lemma. No CSPRNG in the output path.
// It exposes a CUSE character device at /dev/trandom that behaves like
// a regular file — just open + read. If the daemon isn't running, the
// device doesn't exist and we refuse to start (same semantics as RDSEED
// on a CPU without it).

const TRANDOM_DEVICE: &str = "/dev/trandom";

fn trandom_available() -> bool {
    std::path::Path::new(TRANDOM_DEVICE).exists()
}

fn fill_trandom(buf: &mut [u8]) -> Result<(), RngError> {
    use std::io::Read;
    // Open on every call. The overhead is negligible vs the entropy
    // generation cost, and it avoids holding a global file descriptor
    // that could go stale if trandomd restarts. For hot-path use,
    // a thread-local cached fd would be a future optimization.
    let mut f = std::fs::File::open(TRANDOM_DEVICE)
        .map_err(|e| RngError::Io(format!("{TRANDOM_DEVICE}: {e}")))?;
    f.read_exact(buf)
        .map_err(|e| RngError::Io(format!("{TRANDOM_DEVICE} read: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urandom_fills() {
        set_mode(RngMode::Urandom).unwrap();
        let mut buf = [0u8; 64];
        fill(&mut buf).expect("urandom fill");
        assert!(buf.iter().any(|&b| b != 0));
        // Restore to auto-detected for other tests.
        set_mode(detect_best()).unwrap();
    }

    #[test]
    fn test_mode_parse() {
        assert_eq!(RngMode::parse("urandom"), Some(RngMode::Urandom));
        assert_eq!(RngMode::parse("getrandom"), Some(RngMode::Urandom));
        assert_eq!(RngMode::parse("csprng"), Some(RngMode::Urandom));
        assert_eq!(RngMode::parse("Rdseed"), Some(RngMode::Rdseed));
        assert_eq!(RngMode::parse("hardware"), Some(RngMode::Rdseed));
        assert_eq!(RngMode::parse("rndr"), Some(RngMode::Rndr));
        assert_eq!(RngMode::parse("arm-trng"), Some(RngMode::Rndr));
        assert_eq!(RngMode::parse("trandom"), Some(RngMode::Trandom));
        // "trng" maps to auto-detect (best available ITS source).
        assert!(RngMode::parse("trng").unwrap().is_its() || RngMode::parse("trng") == Some(RngMode::Urandom));
        assert_eq!(RngMode::parse("urandom  "), Some(RngMode::Urandom));
        assert_eq!(RngMode::parse("nonsense"), None);
    }

    #[test]
    fn test_its_classification() {
        assert!(!RngMode::Urandom.is_its());
        assert!(RngMode::Rdseed.is_its());
        assert!(RngMode::Rndr.is_its());
        assert!(RngMode::Trandom.is_its());
    }

    #[test]
    fn test_trandom_detection() {
        // Just verify the detection function doesn't crash.
        // Whether it returns true depends on whether trandomd is running.
        let _avail = trandom_available();
    }

    #[test]
    fn test_auto_detect_returns_valid_mode() {
        let mode = detect_best();
        assert!(matches!(mode, RngMode::Urandom | RngMode::Rdseed | RngMode::Rndr | RngMode::Trandom));
        assert!(set_mode(mode).is_ok());
    }

    #[test]
    fn test_available_backends_includes_urandom() {
        let backends = available_backends();
        assert!(backends.contains(&RngMode::Urandom));
    }

    #[test]
    fn test_hardware_mode_respects_availability() {
        if rdseed_available() {
            assert!(set_mode(RngMode::Rdseed).is_ok());
            let mut buf = [0u8; 32];
            fill(&mut buf).expect("rdseed fill");
            assert!(buf.iter().any(|&b| b != 0));
            set_mode(detect_best()).unwrap();
        } else {
            assert!(matches!(
                set_mode(RngMode::Rdseed),
                Err(RngError::HardwareUnavailable("RDSEED"))
            ));
        }
    }
}
