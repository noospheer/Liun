"""Shamir secret sharing over GF(M61).

Information-theoretically secure secret sharing using polynomial
interpolation over the Mersenne prime field M61 = 2^61 - 1.
Same field as the Liu protocol's polynomial MAC.
"""

from liun.gf61 import (
    M61, add, mul,
    poly_eval_low, lagrange_interpolate, lagrange_basis_at_zero,
    rand_element,
)


def split(secret: int, n: int, k: int, rng=None) -> list:
    """Split a secret into n shares with threshold k.

    Args:
        secret: Element of GF(M61) to share.
        n: Total number of shares to generate.
        k: Minimum shares needed to reconstruct (threshold).
        rng: Optional random.Random instance for deterministic tests.

    Returns:
        List of (x_i, y_i) tuples where x_i in {1..n} and y_i = f(x_i).
        f is a random degree-(k-1) polynomial with f(0) = secret.
    """
    if not (0 <= secret < M61):
        raise ValueError(f"Secret must be in [0, M61), got {secret}")
    if k < 1:
        raise ValueError(f"Threshold k must be >= 1, got {k}")
    if n < k:
        raise ValueError(f"n must be >= k, got n={n}, k={k}")

    # Build random polynomial: coeffs[0] = secret, coeffs[1..k-1] random
    coeffs = [secret] + [rand_element(rng) for _ in range(k - 1)]

    # Evaluate at x = 1, 2, ..., n
    shares = []
    for i in range(1, n + 1):
        y = poly_eval_low(coeffs, i)
        shares.append((i, y))

    return shares


def reconstruct(shares: list) -> int:
    """Reconstruct the secret from k or more shares.

    Args:
        shares: List of (x_i, y_i) tuples.

    Returns:
        The secret f(0) via Lagrange interpolation at x=0.
    """
    if not shares:
        raise ValueError("Need at least one share")

    return lagrange_interpolate(shares, 0)


def reconstruct_at(shares: list, target: int) -> int:
    """Reconstruct the polynomial value at an arbitrary point.

    Args:
        shares: List of (x_i, y_i) tuples.
        target: The x-value to evaluate at.

    Returns:
        f(target) via Lagrange interpolation.
    """
    return lagrange_interpolate(shares, target)


def consistency_check(shares: list, degree: int) -> list:
    """Detect corrupt shares by checking polynomial consistency.

    Given N shares that should lie on a degree-d polynomial, uses
    leave-one-out interpolation to identify inconsistent shares.

    Args:
        shares: List of (x_i, y_i) tuples. Must have len > degree + 1.
        degree: Expected polynomial degree.

    Returns:
        List of indices into shares that are inconsistent.
    """
    n = len(shares)
    if n <= degree + 1:
        return []

    corrupt = []
    for i in range(n):
        # Pick degree+1 shares excluding i
        others = [s for j, s in enumerate(shares) if j != i][:degree + 1]
        expected = lagrange_interpolate(others, shares[i][0])
        if expected != shares[i][1]:
            corrupt.append(i)

    return corrupt
