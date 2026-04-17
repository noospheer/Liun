//! # Cascade information reconciliation
//!
//! Rust port of `Liup/src/liuproto/reconciliation.py`. Given two bit strings
//! `bits_a` (reference) and `bits_b` (to correct), run multiple cascade passes
//! of parity checks with binary-search error location until the strings agree.
//!
//! ## Leakage bound (proved in Liup's reconciliation.py docstring)
//!
//! Each parity comparison reveals one linear function (mod-2) of a subset
//! of key bits. By chain-rule entropy: `I(K; transcript) ≤ λ` where `λ` is
//! the number of parity comparisons. `cascade_reconcile` returns this λ;
//! the caller feeds it into privacy amplification's `n_secure` computation.
//!
//! ## Permutation seed
//!
//! Passes after the first permute the bit indices so parities stay
//! approximately independent. Alice and Bob must use the **same permutation
//! order** to produce matching parities. In-process: pass a shared seed.
//! Over a network: either (a) exchange the seed openly (it's not secret,
//! since the permutation is public) or (b) derive it from a shared nonce.

/// Deterministic Fisher-Yates shuffle using a xorshift64 PRNG seeded by `seed`.
/// Returns the permutation as a Vec<usize> of length n.
fn permutation(n: usize, seed: u64) -> Vec<usize> {
    let mut state = if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed };
    let mut out: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let j = (state as usize) % (i + 1);
        out.swap(i, j);
    }
    out
}

/// Correct one error in `bits_fix[lo..hi]` using binary search against
/// `bits_ref[lo..hi]`. Returns the number of parity comparisons made.
fn binary_search_correct(
    bits_ref: &[u8],
    bits_fix: &mut [u8],
    mut lo: usize,
    mut hi: usize,
) -> usize {
    let mut leaked = 0;
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        let par_ref: u8 = bits_ref[lo..mid].iter().fold(0u8, |a, &b| a ^ (b & 1));
        let par_fix: u8 = bits_fix[lo..mid].iter().fold(0u8, |a, &b| a ^ (b & 1));
        leaked += 1;
        if par_ref != par_fix {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    // `lo` is the error position.
    bits_fix[lo] = bits_ref[lo];
    leaked
}

/// In-process cascade: correct `bits_b` to match `bits_a`.
///
/// Parameters:
/// - `bits_a`: reference bits (Alice, read-only)
/// - `bits_b`: bits to correct (Bob, modified in place)
/// - `n_passes`: number of cascade passes (default 10 in Liup)
/// - `initial_block`: initial block size (default 8 in Liup)
/// - `permutation_seed`: seed for the post-first-pass permutations.
///   Alice and Bob must use the same seed.
///
/// Returns the number of parity comparisons performed (= upper bound
/// on leaked bits `λ` by the LHL/Cascade theorem).
pub fn cascade_reconcile(
    bits_a: &[u8],
    bits_b: &mut [u8],
    n_passes: usize,
    initial_block: usize,
    permutation_seed: u64,
) -> usize {
    let n = bits_a.len();
    if n == 0 || bits_b.len() != n { return 0; }

    let initial_block = if initial_block == 0 { 8 } else { initial_block };
    let mut total_leaked = 0;

    // Working buffers for each pass
    let mut ref_work: Vec<u8> = bits_a.to_vec();
    let mut fix_work: Vec<u8> = bits_b.to_vec();

    for pass_idx in 0..n_passes {
        let block_size = (initial_block * (1usize << pass_idx)).min(n).max(1);

        // Choose permutation for this pass (identity on first pass).
        let perm: Vec<usize> = if pass_idx == 0 {
            (0..n).collect()
        } else {
            // Pass-specific seed derived from the shared permutation_seed.
            permutation(n, permutation_seed.wrapping_add(pass_idx as u64))
        };
        let inv_perm: Vec<usize> = {
            let mut inv = vec![0usize; n];
            for (i, &p) in perm.iter().enumerate() { inv[p] = i; }
            inv
        };

        // Permute both ref and fix into working buffers.
        if pass_idx > 0 {
            let ref_src: Vec<u8> = perm.iter().map(|&p| ref_work[p]).collect();
            let fix_src: Vec<u8> = perm.iter().map(|&p| fix_work[p]).collect();
            ref_work = ref_src;
            fix_work = fix_src;
        }

        // Process each block.
        let mut start = 0;
        while start < n {
            let end = (start + block_size).min(n);
            let par_ref: u8 = ref_work[start..end].iter().fold(0u8, |a, &b| a ^ (b & 1));
            let par_fix: u8 = fix_work[start..end].iter().fold(0u8, |a, &b| a ^ (b & 1));
            total_leaked += 1;
            if par_ref != par_fix {
                total_leaked += binary_search_correct(&ref_work, &mut fix_work, start, end);
            }
            start += block_size;
        }

        // Un-permute back for next pass (or final output).
        if pass_idx > 0 {
            let ref_unperm: Vec<u8> = inv_perm.iter().map(|&p| ref_work[p]).collect();
            let fix_unperm: Vec<u8> = inv_perm.iter().map(|&p| fix_work[p]).collect();
            ref_work = ref_unperm;
            fix_work = fix_unperm;
        }
    }

    // Write corrections back.
    bits_b.copy_from_slice(&fix_work);
    total_leaked
}

/// Deterministic upper bound on Cascade leakage for a given `n`, `n_passes`,
/// and `initial_block`. Corresponds to Liup's `leakage_bound`.
pub fn leakage_bound(n: usize, n_passes: usize, initial_block: usize) -> usize {
    if n == 0 { return 0; }
    let initial_block = if initial_block == 0 { 8 } else { initial_block };
    let mut total = 0;
    for pass_idx in 0..n_passes {
        let block_size = (initial_block * (1usize << pass_idx)).min(n);
        let n_blocks = n.div_ceil(block_size);
        let max_bisect = if block_size > 1 {
            (block_size as f64).log2().ceil() as usize
        } else { 0 };
        total += n_blocks * (1 + max_bisect);
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_errors_no_work() {
        let a = vec![0, 1, 1, 0, 1, 0, 0, 1];
        let mut b = a.clone();
        let leaked = cascade_reconcile(&a, &mut b, 5, 4, 42);
        assert_eq!(a, b);
        // Even with no errors, each pass does n/block parity checks.
        assert!(leaked > 0);
    }

    #[test]
    fn test_one_error_corrected() {
        let a: Vec<u8> = (0..64).map(|i| (i % 2) as u8).collect();
        let mut b = a.clone();
        b[17] ^= 1;
        let _ = cascade_reconcile(&a, &mut b, 8, 8, 0xDEAD);
        assert_eq!(a, b, "single error should be corrected");
    }

    #[test]
    fn test_many_errors_corrected() {
        let a: Vec<u8> = (0..256).map(|i| ((i * 13 + 7) % 2) as u8).collect();
        let mut b = a.clone();
        // Flip ~5% of bits.
        for i in (0..256).step_by(19) { b[i] ^= 1; }
        let diffs_before = a.iter().zip(b.iter()).filter(|(x, y)| x != y).count();
        assert!(diffs_before > 10);
        let _ = cascade_reconcile(&a, &mut b, 10, 8, 0xCAFE);
        assert_eq!(a, b, "cascade should correct ~5% error rate");
    }

    #[test]
    fn test_leakage_monotone() {
        let n = 128;
        let a: Vec<u8> = (0..n).map(|i| ((i * 7) % 2) as u8).collect();
        // No errors: leakage should be lower than with errors.
        let mut b_noerror = a.clone();
        let leaked_0 = cascade_reconcile(&a, &mut b_noerror, 8, 8, 0x1234);

        let mut b_error = a.clone();
        for i in (0..n).step_by(11) { b_error[i] ^= 1; }
        let leaked_k = cascade_reconcile(&a, &mut b_error, 8, 8, 0x1234);

        assert!(leaked_k > leaked_0,
            "errors should increase leakage (got {leaked_0} vs {leaked_k})");
    }

    #[test]
    fn test_leakage_bound_is_upper_bound() {
        let n = 100;
        let bound = leakage_bound(n, 10, 8);
        let a: Vec<u8> = (0..n).map(|i| ((i * 3) % 2) as u8).collect();
        let mut b = a.clone();
        // Pathological: flip every bit.
        for i in 0..n { b[i] ^= 1; }
        let actual = cascade_reconcile(&a, &mut b, 10, 8, 0xBEEF);
        assert!(actual <= bound,
            "actual leakage {actual} exceeded theoretical bound {bound}");
    }

    #[test]
    fn test_permutation_is_a_permutation() {
        let n = 100;
        let perm = permutation(n, 0xCAFE_BABE);
        let mut seen = vec![false; n];
        for &p in &perm {
            assert!(p < n, "permutation index out of range");
            assert!(!seen[p], "permutation has duplicate index {p}");
            seen[p] = true;
        }
    }
}
