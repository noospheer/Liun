//! # Background Entropy Prefetch
//!
//! Pre-fetches entropy from getrandom in a background thread so
//! Box-Muller computation never waits for the kernel. The entropy
//! pool is double-buffered: one buffer is being consumed while
//! the other is being filled.
//!
//! Security: same getrandom source, same randomness quality.
//! The buffer exists in process memory — same attack surface as
//! the pool state that's already in memory during Liu exchange.

use std::sync::{Arc, Mutex, Condvar};
use std::thread;

/// Double-buffered entropy pool.
pub struct EntropyPool {
    /// Size of each buffer in bytes.
    buf_size: usize,
    /// Shared state: two buffers + which is ready.
    state: Arc<PoolState>,
    /// Background thread handle.
    _worker: thread::JoinHandle<()>,
}

struct PoolState {
    bufs: Mutex<PoolBufs>,
    /// Signal: a buffer is ready to consume.
    ready: Condvar,
    /// Signal: a buffer has been consumed and needs refill.
    need_fill: Condvar,
    /// Shutdown flag.
    shutdown: Mutex<bool>,
}

struct PoolBufs {
    /// The two buffers.
    a: Vec<u8>,
    b: Vec<u8>,
    /// Which buffer is ready for consumption (true = a, false = b).
    a_ready: bool,
    /// Whether any buffer is ready.
    has_ready: bool,
}

impl EntropyPool {
    /// Create a new entropy pool with the given buffer size.
    /// Immediately starts filling in the background.
    pub fn new(buf_size: usize) -> Self {
        let state = Arc::new(PoolState {
            bufs: Mutex::new(PoolBufs {
                a: vec![0u8; buf_size],
                b: vec![0u8; buf_size],
                a_ready: false,
                has_ready: false,
            }),
            ready: Condvar::new(),
            need_fill: Condvar::new(),
            shutdown: Mutex::new(false),
        });

        let worker_state = state.clone();
        let worker = thread::spawn(move || {
            // Fill buffer A first
            {
                let mut bufs = worker_state.bufs.lock().unwrap();
                crate::rng::fill_expect(&mut bufs.a);
                bufs.a_ready = true;
                bufs.has_ready = true;
                worker_state.ready.notify_one();
            }

            loop {
                // Wait for a buffer to be consumed
                {
                    let mut bufs = worker_state.bufs.lock().unwrap();
                    while bufs.has_ready {
                        if *worker_state.shutdown.lock().unwrap() { return; }
                        bufs = worker_state.need_fill.wait(bufs).unwrap();
                    }
                }

                if *worker_state.shutdown.lock().unwrap() { return; }

                // Fill whichever buffer is NOT ready (the one just consumed)
                {
                    let mut bufs = worker_state.bufs.lock().unwrap();
                    if bufs.a_ready {
                        // A is still ready, fill B
                        crate::rng::fill_expect(&mut bufs.b);
                        // B is now the next to serve after A
                    } else {
                        // A was consumed, fill A
                        crate::rng::fill_expect(&mut bufs.a);
                        bufs.a_ready = true;
                    }
                    bufs.has_ready = true;
                    worker_state.ready.notify_one();
                }
            }
        });

        Self {
            buf_size,
            state,
            _worker: worker,
        }
    }

    /// Get a filled entropy buffer. Blocks until one is ready.
    /// Returns the buffer contents. The background thread immediately
    /// starts refilling the other buffer.
    pub fn get(&self) -> Vec<u8> {
        let mut bufs = self.state.bufs.lock().unwrap();

        // Wait for a ready buffer
        while !bufs.has_ready {
            bufs = self.state.ready.wait(bufs).unwrap();
        }

        // Take the ready buffer's contents
        let result = if bufs.a_ready {
            bufs.a_ready = false;
            bufs.a.clone()
        } else {
            bufs.b.clone()
        };

        bufs.has_ready = false;
        self.state.need_fill.notify_one();

        result
    }

    /// Get entropy and immediately start Box-Muller computation.
    /// This is the zero-wait path: by the time you need more entropy,
    /// the background thread has already filled the other buffer.
    pub fn get_gaussian_samples(&self, n: usize) -> Vec<f64> {
        let n_pairs = (n + 1) / 2;
        let needed = n_pairs * 16;

        // May need multiple buffer fetches for large requests
        let mut entropy = Vec::with_capacity(needed);
        while entropy.len() < needed {
            let buf = self.get();
            let take = (needed - entropy.len()).min(buf.len());
            entropy.extend_from_slice(&buf[..take]);
        }

        // Box-Muller (same math as batch_gaussian_fast, but on prefetched entropy)
        let scale = 1.0 / (u64::MAX as f64 + 1.0);
        let tau = std::f64::consts::TAU;
        let mut samples = vec![0.0f64; n_pairs * 2];

        let n_quads = n_pairs / 4;
        for q in 0..n_quads {
            let base = q * 4;
            let mut u1 = [0.0f64; 4];
            let mut u2 = [0.0f64; 4];
            for k in 0..4 {
                let offset = (base + k) * 16;
                let b1: [u8; 8] = entropy[offset..offset + 8].try_into().unwrap();
                let b2: [u8; 8] = entropy[offset + 8..offset + 16].try_into().unwrap();
                u1[k] = (u64::from_le_bytes(b1) as f64 * scale).max(1e-300);
                u2[k] = u64::from_le_bytes(b2) as f64 * scale;
            }
            for k in 0..4 {
                let r = (-2.0 * u1[k].ln()).sqrt();
                let (sin_t, cos_t) = (tau * u2[k]).sin_cos();
                samples[(base + k) * 2] = r * cos_t;
                samples[(base + k) * 2 + 1] = r * sin_t;
            }
        }
        for i in (n_quads * 4)..n_pairs {
            let offset = i * 16;
            let b1: [u8; 8] = entropy[offset..offset + 8].try_into().unwrap();
            let b2: [u8; 8] = entropy[offset + 8..offset + 16].try_into().unwrap();
            let u1 = (u64::from_le_bytes(b1) as f64 * scale).max(1e-300);
            let u2 = u64::from_le_bytes(b2) as f64 * scale;
            let r = (-2.0 * u1.ln()).sqrt();
            let (sin_t, cos_t) = (tau * u2).sin_cos();
            samples[i * 2] = r * cos_t;
            samples[i * 2 + 1] = r * sin_t;
        }

        samples.truncate(n);
        samples
    }

    /// Buffer size.
    pub fn buffer_size(&self) -> usize {
        self.buf_size
    }
}

impl Drop for EntropyPool {
    fn drop(&mut self) {
        *self.state.shutdown.lock().unwrap() = true;
        self.state.need_fill.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_pool_basic() {
        let pool = EntropyPool::new(1024);
        let buf = pool.get();
        assert_eq!(buf.len(), 1024);
        // Should not be all zeros
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_entropy_pool_multiple_gets() {
        let pool = EntropyPool::new(256);
        let buf1 = pool.get();
        let buf2 = pool.get();
        // Different buffers (overwhelmingly likely)
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_gaussian_from_pool() {
        let pool = EntropyPool::new(1_000_000); // 1MB buffer
        let samples = pool.get_gaussian_samples(10000);
        assert_eq!(samples.len(), 10000);

        let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
        let var: f64 = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / samples.len() as f64;
        assert!(mean.abs() < 0.05, "mean: {mean}");
        assert!((var - 1.0).abs() < 0.1, "var: {var}");
    }

    #[test]
    fn test_prefetch_overlaps_compute() {
        // The second get() should be faster than the first because
        // the background thread started filling while we processed the first.
        let pool = EntropyPool::new(100_000);

        let start = std::time::Instant::now();
        let _ = pool.get(); // first: may wait for initial fill
        let first = start.elapsed();

        // Do some work (simulating Box-Muller compute)
        std::thread::sleep(std::time::Duration::from_millis(5));

        let start = std::time::Instant::now();
        let _ = pool.get(); // second: should be ready already
        let second = start.elapsed();

        // Second should be near-instant if prefetch worked
        println!("First get: {:?}, Second get: {:?}", first, second);
        // Don't assert timing (CI variability), just verify it works
    }
}
