use liuproto_core::gf61::Gf61;
use liuproto_core::mac::{mac_tag, mac_tag_parallel4, mac_tag_scalar};
use std::hint::black_box;
use std::time::Instant;

fn measure<F: Fn()>(label: &str, n: usize, iters: usize, f: F) {
    // Warmup
    for _ in 0..5 { f(); }
    let start = Instant::now();
    for _ in 0..iters { f(); }
    let elapsed = start.elapsed();
    let per = elapsed / iters as u32;
    let us = per.as_micros();
    let mcoef_per_sec = n as f64 / per.as_secs_f64() / 1e6;
    println!("  {label:<14} {us:>5} µs   {mcoef_per_sec:>7.1} M coef/s");
}

fn main() {
    let n = 113_000;
    let coeffs: Vec<Gf61> = (0..n).map(|i| Gf61::new(i as u64 * 7 + 3)).collect();
    let r = Gf61::new(123_456_789);
    let s = Gf61::new(987_654_321);

    println!("MAC benchmark, n = {n} coefficients, 100 iters per variant:");
    measure("scalar   ", n, 100, || {
        black_box(mac_tag_scalar(black_box(&coeffs), black_box(r), black_box(s)));
    });
    measure("parallel4", n, 100, || {
        black_box(mac_tag_parallel4(black_box(&coeffs), black_box(r), black_box(s)));
    });
    measure("auto     ", n, 100, || {
        black_box(mac_tag(black_box(&coeffs), black_box(r), black_box(s)));
    });
    println!("(Python C extension baseline: ~520 µs for this workload)");
}
