"""GF(M61) field arithmetic — core primitive for Liun.

All operations over the Mersenne prime field M61 = 2^61 - 1.
Uses Python int (not numpy uint64) to avoid overflow on 61x61-bit multiply.
Shared field with the Liu protocol's polynomial MAC.
"""

import secrets

M61 = (1 << 61) - 1  # 2^61 - 1 = 2305843009213693951


def _reduce(x: int) -> int:
    """Fast reduction mod M61 using Mersenne prime structure.

    For x < 2^122 (product of two 61-bit numbers):
      x mod (2^61 - 1) = (x >> 61) + (x & M61), with a final correction.
    """
    # First reduction: split into high and low 61-bit halves
    r = (x >> 61) + (x & M61)
    # r might be >= M61 (at most 2*M61 - 1), so fix up
    if r >= M61:
        r -= M61
    return r


def add(a: int, b: int) -> int:
    """(a + b) mod M61."""
    s = a + b
    if s >= M61:
        s -= M61
    return s


def sub(a: int, b: int) -> int:
    """(a - b) mod M61."""
    s = a - b
    if s < 0:
        s += M61
    return s


def mul(a: int, b: int) -> int:
    """(a * b) mod M61. Python int handles 122-bit intermediate."""
    return _reduce(a * b)


def neg(a: int) -> int:
    """(-a) mod M61."""
    return M61 - a if a != 0 else 0


def inv(a: int) -> int:
    """Multiplicative inverse via Fermat's little theorem: a^(M61-2) mod M61.

    For Mersenne prime p, a^(-1) = a^(p-2) mod p.
    Uses Python's built-in modular exponentiation (fast square-and-multiply).
    """
    if a == 0:
        raise ZeroDivisionError("Cannot invert zero in GF(M61)")
    return pow(a, M61 - 2, M61)


def div(a: int, b: int) -> int:
    """(a / b) mod M61 = a * b^(-1) mod M61."""
    return mul(a, inv(b))


def poly_eval(coeffs: list, x: int) -> int:
    """Evaluate polynomial at x using Horner's method.

    coeffs = [a_d, a_{d-1}, ..., a_1, a_0] (highest degree first)
    Returns a_d * x^d + ... + a_1 * x + a_0  mod M61.
    """
    result = 0
    for c in coeffs:
        result = add(mul(result, x), c)
    return result


def poly_eval_low(coeffs: list, x: int) -> int:
    """Evaluate polynomial at x using Horner's method.

    coeffs = [a_0, a_1, ..., a_d] (lowest degree first)
    Returns a_0 + a_1 * x + ... + a_d * x^d  mod M61.
    """
    result = 0
    for c in reversed(coeffs):
        result = add(mul(result, x), c)
    return result


def lagrange_interpolate(points: list, x: int) -> int:
    """Evaluate the interpolating polynomial at x given a set of points.

    points = [(x_0, y_0), (x_1, y_1), ...] over GF(M61).
    Uses the Lagrange basis form: L(x) = sum_i y_i * prod_{j!=i} (x - x_j)/(x_i - x_j).
    """
    n = len(points)
    result = 0
    for i in range(n):
        xi, yi = points[i]
        # Compute Lagrange basis polynomial L_i(x)
        num = 1  # numerator product
        den = 1  # denominator product
        for j in range(n):
            if j == i:
                continue
            xj = points[j][0]
            num = mul(num, sub(x, xj))
            den = mul(den, sub(xi, xj))
        basis = mul(num, inv(den))
        result = add(result, mul(yi, basis))
    return result


def lagrange_basis_at_zero(xs: list, i: int) -> int:
    """Compute Lagrange basis coefficient L_i(0) for evaluation at x=0.

    xs = list of x-coordinates.
    Returns prod_{j!=i} (0 - x_j) / (x_i - x_j) mod M61.
    """
    xi = xs[i]
    num = 1
    den = 1
    for j, xj in enumerate(xs):
        if j == i:
            continue
        num = mul(num, neg(xj))       # (0 - x_j)
        den = mul(den, sub(xi, xj))   # (x_i - x_j)
    return mul(num, inv(den))


def lagrange_basis_at(xs: list, i: int, target: int) -> int:
    """Compute Lagrange basis coefficient L_i(target).

    xs = list of x-coordinates.
    Returns prod_{j!=i} (target - x_j) / (x_i - x_j) mod M61.
    """
    xi = xs[i]
    num = 1
    den = 1
    for j, xj in enumerate(xs):
        if j == i:
            continue
        num = mul(num, sub(target, xj))
        den = mul(den, sub(xi, xj))
    return mul(num, inv(den))


def newton_coefficients(points: list) -> tuple:
    """Compute Newton divided difference coefficients from points.

    O(n^2) setup. Returns (xs, coeffs) for use with newton_eval.
    points = [(x_0, y_0), ..., (x_{n-1}, y_{n-1})].
    """
    n = len(points)
    xs = [p[0] for p in points]
    d = [p[1] for p in points]

    for j in range(1, n):
        for i in range(n - 1, j - 1, -1):
            d[i] = div(sub(d[i], d[i - 1]), sub(xs[i], xs[i - j]))

    return xs, d


def newton_eval(xs: list, coeffs: list, t: int) -> int:
    """Evaluate Newton-form polynomial at t in O(n).

    Uses Horner-like scheme on the Newton basis:
    p(t) = c[n-1]*(t-x[n-2])*...*(t-x[0]) + ... + c[1]*(t-x[0]) + c[0]
    """
    n = len(coeffs)
    result = coeffs[n - 1]
    for i in range(n - 2, -1, -1):
        result = add(mul(result, sub(t, xs[i])), coeffs[i])
    return result


class InterpolatingPoly:
    """Precomputed polynomial from points for fast multi-evaluation.

    O(n^2) construction, O(n) per evaluation.
    """

    __slots__ = ('xs', 'coeffs', 'n')

    def __init__(self, points: list):
        self.xs, self.coeffs = newton_coefficients(points)
        self.n = len(points)

    def eval_at(self, t: int) -> int:
        return newton_eval(self.xs, self.coeffs, t)


def rand_element(rng=None) -> int:
    """Sample a uniform random element from GF(M61) via rejection sampling.

    Uses 64-bit random, rejects if >= M61.
    """
    while True:
        if rng is not None:
            r = rng.getrandbits(61)
        else:
            r = secrets.randbits(61)
        if r < M61:
            return r


def rand_nonzero(rng=None) -> int:
    """Sample a uniform random nonzero element from GF(M61)."""
    while True:
        r = rand_element(rng)
        if r != 0:
            return r
