use liuproto_core::noise::batch_gaussian;
use liuproto_core::entropy::EntropyPool;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let n = 100_000;
    let iters = 30;

    // Pre-create the entropy pool (background thread starts filling)
    let pool = EntropyPool::new(n * 16); // enough for one batch

    // Warmup
    for _ in 0..3 {
        black_box(batch_gaussian(n));
        black_box(pool.get_gaussian_samples(n));
    }

    // Benchmark: standard (getrandom inline)
    let start = Instant::now();
    for _ in 0..iters {
        black_box(batch_gaussian(n));
    }
    let standard_time = start.elapsed() / iters;

    // Benchmark: prefetch (background entropy)
    let start = Instant::now();
    for _ in 0..iters {
        black_box(pool.get_gaussian_samples(n));
    }
    let prefetch_time = start.elapsed() / iters;

    let speedup = standard_time.as_secs_f64() / prefetch_time.as_secs_f64();

    println!("Gaussian noise ({n} samples):");
    println!("  Standard (inline getrandom):   {:>6} µs  ({:.1} M samples/sec)",
        standard_time.as_micros(),
        n as f64 / standard_time.as_secs_f64() / 1e6);
    println!("  Prefetch (background entropy):  {:>6} µs  ({:.1} M samples/sec)",
        prefetch_time.as_micros(),
        n as f64 / prefetch_time.as_secs_f64() / 1e6);
    println!("  Speedup: {speedup:.2}x");
}
