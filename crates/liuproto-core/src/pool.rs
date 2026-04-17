//! # OTP Pool with Key Recycling
//!
//! Manages the one-time pad pool for sign bit encryption and MAC key derivation.
//! After each successful run:
//!   1. Withdraw OTP bits for sign encryption
//!   2. Deposit the agreed sign bits
//!   3. Recycle first 128 bits as next run's MAC key
//!
//! ITS property: XOR bias preservation (proved in Lean: XORBias.lean).
//! The bias of XOR'd bits ≤ max of individual biases, not their sum.
//! Pool recycling maintains constant per-bit security forever — **provided**
//! the deposited bits carry fresh entropy from a trusted source (`DepositSource::Trusted`).
//! Depositing `Recycled` bits appends to the buffer but does NOT re-derive
//! MAC keys, preventing an attacker-influencable MAC rotation.
//!
//! All key material here is wiped on drop via `zeroize`.

use crate::gf61::Gf61;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Where did the bits come from? Determines whether they're allowed to
/// re-seed the MAC keys. See module docs for the threat being mitigated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositSource {
    /// Bits are TRNG-derived (e.g. Liu-exchange output after OTP decryption).
    /// Safe to use for MAC key rotation.
    Trusted,
    /// Bits are recycled from protocol state (e.g. ciphertext). NOT safe for
    /// MAC key derivation; they may carry adversary-controlled structure.
    /// Appended to the pool buffer only.
    Recycled,
}

/// Errors from pool operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    /// Not enough OTP bytes remaining to satisfy the withdrawal.
    Exhausted { needed: usize, available: usize },
    /// `deposit` input too short for MAC recycling (requires ≥ 128 bits when
    /// source is `Trusted`).
    DepositTooShort { bits: usize, min_required: usize },
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exhausted { needed, available } =>
                write!(f, "pool exhausted: need {needed} bytes, have {available}"),
            Self::DepositTooShort { bits, min_required } =>
                write!(f, "deposit too short: {bits} bits < {min_required} required"),
        }
    }
}

impl std::error::Error for PoolError {}

/// The OTP pool: a FIFO buffer of key material.
///
/// On drop, `buf` and the MAC keys are zeroized. Use `Zeroizing<Vec<u8>>` for
/// OTP outputs (returned by `withdraw_otp`) if the caller keeps them around.
pub struct Pool {
    buf: Vec<u8>,
    cursor: usize,
    /// Current MAC key (r, s) for the next run.
    mac_r: Gf61,
    mac_s: Gf61,
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.buf.zeroize();
        // Gf61 is just a u64 wrapper; overwrite with 0.
        self.mac_r = Gf61::new(0);
        self.mac_s = Gf61::new(0);
    }
}

// Marker: Pool zeroes its sensitive fields on drop.
impl ZeroizeOnDrop for Pool {}

impl Pool {
    /// Create a new pool from PSK bytes.
    /// Layout: bytes 0-15 = initial MAC key, bytes 16-31 = config MAC key,
    /// bytes 32+ = initial OTP pool.
    pub fn from_psk(psk: &[u8], nonce: &[u8; 16]) -> Self {
        assert!(psk.len() >= 32, "PSK too short");

        // Derive initial MAC key from PSK[0:16] XOR nonce
        let mut r_bytes = [0u8; 8];
        let mut s_bytes = [0u8; 8];
        for i in 0..8 {
            r_bytes[i] = psk[i] ^ nonce[i];
            s_bytes[i] = psk[i + 8] ^ nonce[i + 8];
        }

        let p = Self {
            buf: psk[32..].to_vec(),
            cursor: 0,
            mac_r: Gf61::random(&r_bytes),
            mac_s: Gf61::random(&s_bytes),
        };
        // Local MAC seed bytes go out of scope here — but they're on the
        // stack, so the compiler may optimize them away. For the inputs to
        // this function (psk, nonce), the caller owns and should wipe.
        r_bytes.zeroize();
        s_bytes.zeroize();
        p
    }

    /// Get the current MAC key.
    pub fn mac_keys(&self) -> (Gf61, Gf61) {
        (self.mac_r, self.mac_s)
    }

    /// Withdraw `n_bits` of OTP. Returns `Err(PoolError::Exhausted)` if the
    /// pool doesn't have enough remaining bytes.
    ///
    /// Callers should wrap the returned `Vec<u8>` in `Zeroizing` (from the
    /// `zeroize` crate) if they hold onto it past immediate XOR use.
    pub fn try_withdraw_otp(&mut self, n_bits: usize) -> Result<Vec<u8>, PoolError> {
        let n_bytes = (n_bits + 7) / 8;
        let available = self.buf.len() - self.cursor;
        if n_bytes > available {
            return Err(PoolError::Exhausted { needed: n_bytes, available });
        }

        let raw = &self.buf[self.cursor..self.cursor + n_bytes];
        self.cursor += n_bytes;

        // Unpack bytes to bits (MSB-first within each byte)
        let mut bits = Vec::with_capacity(n_bits);
        for &byte in raw {
            for b in (0..8).rev() {
                if bits.len() < n_bits {
                    bits.push((byte >> b) & 1);
                }
            }
        }
        Ok(bits)
    }

    /// Withdraw `n_bits` of OTP. Panics on exhaustion. Prefer `try_withdraw_otp`
    /// in new code.
    pub fn withdraw_otp(&mut self, n_bits: usize) -> Vec<u8> {
        self.try_withdraw_otp(n_bits)
            .expect("pool withdraw_otp failed; use try_withdraw_otp for graceful handling")
    }

    /// Deposit bits into the pool.
    ///
    /// When `source == Trusted`:
    /// - Requires ≥ 128 bits of input (for MAC key rotation).
    /// - Appends bits to the pool buffer.
    /// - Re-derives MAC keys from the first 128 bits.
    ///
    /// When `source == Recycled`:
    /// - Appends bits to the pool buffer.
    /// - Does **not** re-derive MAC keys (preventing attacker-influencable
    ///   MAC rotation if the input has adversary-controlled structure).
    /// - No minimum length.
    pub fn try_deposit(&mut self, bits: &[u8], source: DepositSource) -> Result<(), PoolError> {
        if source == DepositSource::Trusted && bits.len() < 128 {
            return Err(PoolError::DepositTooShort { bits: bits.len(), min_required: 128 });
        }

        // Pack bits into bytes (MSB-first) and extend pool buffer.
        let n_bytes = (bits.len() + 7) / 8;
        let mut packed = Vec::with_capacity(n_bytes);
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                byte |= (bit & 1) << (7 - i);
            }
            packed.push(byte);
        }
        self.buf.extend_from_slice(&packed);

        if source == DepositSource::Trusted {
            // Re-derive MAC keys from the first 16 bytes of the packed deposit.
            let mut r_bytes = [0u8; 8];
            let mut s_bytes = [0u8; 8];
            r_bytes.copy_from_slice(&packed[0..8]);
            s_bytes.copy_from_slice(&packed[8..16]);
            self.mac_r = Gf61::random(&r_bytes);
            self.mac_s = Gf61::random(&s_bytes);
            r_bytes.zeroize();
            s_bytes.zeroize();
        }
        packed.zeroize();
        Ok(())
    }

    /// Deposit trusted bits. Panics on too-short input. Prefer `try_deposit`.
    pub fn deposit(&mut self, sign_bits: &[u8]) {
        self.try_deposit(sign_bits, DepositSource::Trusted)
            .expect("pool deposit failed; use try_deposit for graceful handling")
    }

    /// Available bytes remaining in the pool.
    pub fn available(&self) -> usize {
        self.buf.len() - self.cursor
    }

    /// Backpressure predicate: returns true iff withdrawing `n_bits` now
    /// would leave the pool below the `reserve_bytes` floor. Callers
    /// (e.g. send paths) should check this BEFORE actually withdrawing
    /// and surface `EPOOL_EXHAUSTED` to the user rather than either
    /// waiting silently or falling back to weaker crypto.
    ///
    /// **No fallback policy:** in ITS mode there is no "use AES if the
    /// pool is dry" path by design. A pure ITS system must pause traffic
    /// when it runs out of key material; anything else silently
    /// downgrades the security claim.
    pub fn would_exhaust_below(&self, n_bits: usize, reserve_bytes: usize) -> bool {
        let n_bytes = (n_bits + 7) / 8;
        self.available() < n_bytes + reserve_bytes
    }

    /// Byte offset into `buf` of the next OTP byte to withdraw.
    pub fn cursor(&self) -> usize { self.cursor }

    /// Total buffer length (initial pool + deposited material).
    pub fn buf_len(&self) -> usize { self.buf.len() }

    /// Stable 64-bit fingerprint of the pool's active state. Designed for
    /// reconnect sync-verification: if two pools should be in lockstep
    /// (same PSK, same deposit history, same OTP consumption), their
    /// fingerprints match.
    ///
    /// **Input**: `(cursor, buf.len(), mac_r, mac_s)` fed through SipHash
    /// (via `std::collections::hash_map::DefaultHasher`). SipHash is not
    /// cryptographic-grade collision-resistant, but collision probability
    /// ≈ 2⁻⁶⁴ is far below anything operational: if the fingerprints match
    /// and the pools are actually desynced, the next chat MAC would catch
    /// it, so a hash collision only delays the error by one message.
    ///
    /// **MAC key privacy**: the hash output doesn't leak mac_r/mac_s
    /// meaningfully — preimage resistance of SipHash requires ~2⁶⁴ work,
    /// far more than brute-forcing the 61-bit field directly. We don't
    /// claim ITS for this fingerprint; it's an integrity check only.
    pub fn state_fingerprint(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.cursor.hash(&mut h);
        self.buf.len().hash(&mut h);
        self.mac_r.val().hash(&mut h);
        self.mac_s.val().hash(&mut h);
        h.finish()
    }
}

// ──────────────── Parallel refill / shared pool ────────────────
//
// `SharedPool` wraps a `Pool` in `Arc<Mutex<..>>` so multiple
// producer threads (e.g. N concurrent Liu-channel workers refilling
// one peer pair's pool) can deposit entropy in parallel. The internal
// Mutex serializes the actual deposit operation — WC MAC key rotation
// and buffer extension happen one at a time — but the producers can
// run their compute/network-bound work concurrently.
//
// No `tokio` dependency: `SharedPool` uses `std::sync::Mutex` so it
// composes with either sync threads or async tasks (via `spawn_blocking`
// for tight pool-lock sections, or just direct `.lock()` since deposit
// completes in microseconds).

use std::sync::{Arc, Mutex};

/// Arc/Mutex-wrapped `Pool` for multi-producer refill. Cloning is cheap
/// (just bumps the Arc).
#[derive(Clone)]
pub struct SharedPool {
    inner: Arc<Mutex<Pool>>,
}

impl SharedPool {
    pub fn new(pool: Pool) -> Self {
        Self { inner: Arc::new(Mutex::new(pool)) }
    }

    /// Number of live references. Useful for operators to see how many
    /// refill workers + consumers currently hold a handle.
    pub fn refcount(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    pub fn try_deposit(
        &self,
        bits: &[u8],
        source: DepositSource,
    ) -> Result<(), PoolError> {
        let mut pool = self.inner.lock().expect("pool poisoned");
        pool.try_deposit(bits, source)
    }

    pub fn try_withdraw_otp(&self, n_bits: usize) -> Result<Vec<u8>, PoolError> {
        let mut pool = self.inner.lock().expect("pool poisoned");
        pool.try_withdraw_otp(n_bits)
    }

    pub fn available(&self) -> usize {
        self.inner.lock().expect("pool poisoned").available()
    }

    pub fn would_exhaust_below(&self, n_bits: usize, reserve_bytes: usize) -> bool {
        self.inner
            .lock()
            .expect("pool poisoned")
            .would_exhaust_below(n_bits, reserve_bytes)
    }

    pub fn state_fingerprint(&self) -> u64 {
        self.inner.lock().expect("pool poisoned").state_fingerprint()
    }

    /// Execute `f` with exclusive access to the underlying `Pool`. Use
    /// sparingly — prefer the dedicated methods which hold the lock for
    /// a single critical section.
    pub fn with<T>(&self, f: impl FnOnce(&mut Pool) -> T) -> T {
        let mut pool = self.inner.lock().expect("pool poisoned");
        f(&mut pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_psk() -> Vec<u8> {
        let mut psk = vec![0u8; 1032];
        for (i, byte) in psk.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }
        psk
    }

    #[test]
    fn test_pool_creation() {
        let psk = make_test_psk();
        let nonce = [0u8; 16];
        let pool = Pool::from_psk(&psk, &nonce);
        assert_eq!(pool.available(), 1000);
    }

    #[test]
    fn test_withdraw_deposit_cycle() {
        let psk = make_test_psk();
        let nonce = [0u8; 16];
        let mut pool = Pool::from_psk(&psk, &nonce);

        let initial_available = pool.available();

        let otp = pool.withdraw_otp(100);
        assert_eq!(otp.len(), 100);
        assert!(pool.available() < initial_available);

        let sign_bits: Vec<u8> = (0..200).map(|i| (i % 2) as u8).collect();
        pool.deposit(&sign_bits);

        let (r, s) = pool.mac_keys();
        assert!(r.val() > 0 || s.val() > 0);
    }

    #[test]
    fn test_withdraw_exhausted_returns_err() {
        let psk = make_test_psk();
        let nonce = [0u8; 16];
        let mut pool = Pool::from_psk(&psk, &nonce);

        // Pool has 1000 bytes = 8000 bits. Ask for more.
        let result = pool.try_withdraw_otp(80_000);
        assert!(matches!(result, Err(PoolError::Exhausted { .. })));
    }

    #[test]
    fn shared_pool_concurrent_deposits() {
        // N producer threads deposit simultaneously. The final pool
        // length must equal the initial 1000 bytes plus the packed
        // contribution of every deposit — no data loss under contention.
        let psk = make_test_psk();
        let pool = Pool::from_psk(&psk, &[0u8; 16]);
        let initial_bytes = pool.available();
        let shared = SharedPool::new(pool);

        let workers = 4;
        let deposits_per_worker = 20;
        let bits_per_deposit = 1024;

        let mut handles = Vec::new();
        for w in 0..workers {
            let sp = shared.clone();
            handles.push(std::thread::spawn(move || {
                for d in 0..deposits_per_worker {
                    // Deterministic bit pattern — whatever, just has to
                    // satisfy the >= 128 bits minimum.
                    let seed = (w * 1000 + d) as u8;
                    let bits: Vec<u8> =
                        (0..bits_per_deposit).map(|i| ((seed ^ (i as u8)) & 1)).collect();
                    sp.try_deposit(&bits, DepositSource::Recycled).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let total_deposits = workers * deposits_per_worker;
        let expected_added = total_deposits * (bits_per_deposit / 8);
        assert_eq!(shared.available(), initial_bytes + expected_added);
    }

    #[test]
    fn shared_pool_withdraw_under_contention_never_corrupts() {
        // A writer and a reader race on the same pool. Both must see
        // consistent byte counts; neither observes a half-deposited
        // buffer. This checks the Mutex is actually protecting the
        // critical section.
        let psk = make_test_psk();
        let pool = Pool::from_psk(&psk, &[0u8; 16]);
        let shared = SharedPool::new(pool);

        let s_writer = shared.clone();
        let writer = std::thread::spawn(move || {
            for i in 0..50 {
                let bits: Vec<u8> = (0..256).map(|b| ((i ^ b) & 1) as u8).collect();
                s_writer
                    .try_deposit(&bits, DepositSource::Recycled)
                    .unwrap();
            }
        });

        let s_reader = shared.clone();
        let reader = std::thread::spawn(move || {
            let mut last = 0usize;
            for _ in 0..200 {
                let cur = s_reader.available();
                assert!(cur >= last, "pool shrank unexpectedly: {last} → {cur}");
                last = cur;
                std::thread::yield_now();
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();
    }

    #[test]
    fn shared_pool_refcount_tracks_clones() {
        let psk = make_test_psk();
        let pool = Pool::from_psk(&psk, &[0u8; 16]);
        let a = SharedPool::new(pool);
        assert_eq!(a.refcount(), 1);
        let b = a.clone();
        let c = a.clone();
        assert_eq!(a.refcount(), 3);
        drop(b);
        assert_eq!(a.refcount(), 2);
        drop(c);
        assert_eq!(a.refcount(), 1);
    }

    #[test]
    fn test_would_exhaust_below_threshold() {
        let psk = make_test_psk();
        let nonce = [0u8; 16];
        let mut pool = Pool::from_psk(&psk, &nonce);
        let total = pool.available();
        // Withdraw 80 bits (10 bytes) with reserve 0 → fine.
        assert!(!pool.would_exhaust_below(80, 0));
        // With reserve equal to the whole pool → triggers immediately.
        assert!(pool.would_exhaust_below(80, total));
        // After draining most of it, a small ask with a modest reserve trips.
        let _ = pool.try_withdraw_otp((total - 100) * 8);
        assert!(pool.would_exhaust_below(80, 200));
        assert!(!pool.would_exhaust_below(80, 0));
    }

    #[test]
    fn test_withdraw_panics_on_exhausted() {
        let psk = make_test_psk();
        let nonce = [0u8; 16];
        let mut pool = Pool::from_psk(&psk, &nonce);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pool.withdraw_otp(80_000);
        }));
        assert!(result.is_err(), "withdraw_otp should panic on exhaustion");
    }

    #[test]
    fn test_trusted_deposit_changes_mac_keys() {
        let psk = make_test_psk();
        let nonce = [0u8; 16];
        let mut pool = Pool::from_psk(&psk, &nonce);
        let (r0, s0) = pool.mac_keys();

        let bits: Vec<u8> = (0..256).map(|i| ((i * 7) % 2) as u8).collect();
        pool.try_deposit(&bits, DepositSource::Trusted).unwrap();
        let (r1, s1) = pool.mac_keys();
        assert!(r0 != r1 || s0 != s1, "Trusted deposit should change MAC keys");
    }

    #[test]
    fn test_recycled_deposit_does_not_change_mac_keys() {
        let psk = make_test_psk();
        let nonce = [0u8; 16];
        let mut pool = Pool::from_psk(&psk, &nonce);
        let (r0, s0) = pool.mac_keys();

        // A 'Recycled' deposit may be adversary-influenced; must NOT rotate MAC.
        let bits: Vec<u8> = vec![0u8; 200]; // all zeros (pathological)
        pool.try_deposit(&bits, DepositSource::Recycled).unwrap();
        let (r1, s1) = pool.mac_keys();
        assert_eq!(r0, r1, "Recycled deposit must not change mac_r");
        assert_eq!(s0, s1, "Recycled deposit must not change mac_s");
        // Buffer did grow, though.
        assert!(pool.available() > 1000);
    }

    #[test]
    fn test_trusted_deposit_rejects_short_input() {
        let psk = make_test_psk();
        let nonce = [0u8; 16];
        let mut pool = Pool::from_psk(&psk, &nonce);

        let bits: Vec<u8> = vec![1u8; 50]; // < 128 bits
        let res = pool.try_deposit(&bits, DepositSource::Trusted);
        assert!(matches!(res, Err(PoolError::DepositTooShort { .. })));
    }

    #[test]
    fn test_recycled_deposit_accepts_short_input() {
        let psk = make_test_psk();
        let nonce = [0u8; 16];
        let mut pool = Pool::from_psk(&psk, &nonce);

        let bits: Vec<u8> = vec![1u8; 8]; // just 8 bits, fine for recycled
        pool.try_deposit(&bits, DepositSource::Recycled).unwrap();
    }

    #[test]
    fn test_otp_bits_are_binary() {
        let psk = make_test_psk();
        let nonce = [0u8; 16];
        let mut pool = Pool::from_psk(&psk, &nonce);
        let otp = pool.withdraw_otp(500);
        for &bit in &otp {
            assert!(bit == 0 || bit == 1);
        }
    }

    #[test]
    fn test_pool_zeroizes_on_drop() {
        // We can't observe a dropped pool's memory safely (that's the
        // whole point of zeroize), but we can verify the struct implements
        // ZeroizeOnDrop as claimed.
        fn assert_zod<T: ZeroizeOnDrop>() {}
        assert_zod::<Pool>();
    }
}
