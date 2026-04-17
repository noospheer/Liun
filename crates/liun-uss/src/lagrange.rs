//! # Lagrange Interpolation over GF(M61)
//!
//! Given n points (x_i, y_i), recover the unique polynomial of degree < n
//! and evaluate it at any point. Used for:
//! - Shamir secret reconstruction (evaluate at x = 0)
//! - Signature combination (evaluate at x = message)
//! - Verification (check point consistency)

use liuproto_core::gf61::Gf61;

/// Compute the Lagrange basis polynomial L_i(x) = Π_{j≠i} (x - x_j) / (x_i - x_j).
pub fn lagrange_basis(points_x: &[Gf61], i: usize, x: Gf61) -> Gf61 {
    let mut num = Gf61::ONE;
    let mut den = Gf61::ONE;
    let xi = points_x[i];

    for (j, &xj) in points_x.iter().enumerate() {
        if j != i {
            num = num * (x - xj);
            den = den * (xi - xj);
        }
    }
    num * den.inv()
}

/// Lagrange interpolation: evaluate the unique polynomial through (x_i, y_i) at x.
pub fn interpolate(points_x: &[Gf61], points_y: &[Gf61], x: Gf61) -> Gf61 {
    assert_eq!(points_x.len(), points_y.len(), "mismatched point arrays");
    let mut result = Gf61::ZERO;
    for i in 0..points_x.len() {
        result = result + points_y[i] * lagrange_basis(points_x, i, x);
    }
    result
}

/// Reconstruct the secret: evaluate at x = 0.
pub fn reconstruct_secret(points_x: &[Gf61], points_y: &[Gf61]) -> Gf61 {
    interpolate(points_x, points_y, Gf61::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpolate_line() {
        // y = 2x + 3: points (1, 5), (2, 7)
        let xs = [Gf61::new(1), Gf61::new(2)];
        let ys = [Gf61::new(5), Gf61::new(7)];

        // Evaluate at x = 0: should give 3
        assert_eq!(interpolate(&xs, &ys, Gf61::ZERO).val(), 3);
        // Evaluate at x = 3: should give 9
        assert_eq!(interpolate(&xs, &ys, Gf61::new(3)).val(), 9);
    }

    #[test]
    fn test_interpolate_quadratic() {
        // y = x² + 1: points (1, 2), (2, 5), (3, 10)
        let xs = [Gf61::new(1), Gf61::new(2), Gf61::new(3)];
        let ys = [Gf61::new(2), Gf61::new(5), Gf61::new(10)];

        // Evaluate at x = 0: should give 1
        assert_eq!(interpolate(&xs, &ys, Gf61::ZERO).val(), 1);
        // Evaluate at x = 4: should give 17
        assert_eq!(interpolate(&xs, &ys, Gf61::new(4)).val(), 17);
    }

    #[test]
    fn test_reconstruct_secret() {
        // Secret s = 42, polynomial y = 42 + 7x + 3x²
        // Shares: (1, 52), (2, 68), (3, 90)
        let xs = [Gf61::new(1), Gf61::new(2), Gf61::new(3)];
        let ys = [Gf61::new(52), Gf61::new(68), Gf61::new(90)];
        assert_eq!(reconstruct_secret(&xs, &ys).val(), 42);
    }
}
