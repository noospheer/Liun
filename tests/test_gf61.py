"""Tests for GF(M61) field arithmetic."""

import random
import pytest
from liun.gf61 import (
    M61, add, sub, mul, neg, inv, div,
    poly_eval, poly_eval_low, lagrange_interpolate,
    lagrange_basis_at_zero, rand_element,
)


class TestFieldAxioms:
    """Verify field axioms hold for GF(M61)."""

    def test_closure_add(self, sample_elements):
        for a in sample_elements:
            for b in sample_elements:
                r = add(a, b)
                assert 0 <= r < M61

    def test_closure_mul(self, sample_elements):
        for a in sample_elements:
            for b in sample_elements:
                r = mul(a, b)
                assert 0 <= r < M61

    def test_associativity_add(self, rng):
        for _ in range(20):
            a, b, c = [rand_element(rng) for _ in range(3)]
            assert add(add(a, b), c) == add(a, add(b, c))

    def test_associativity_mul(self, rng):
        for _ in range(20):
            a, b, c = [rand_element(rng) for _ in range(3)]
            assert mul(mul(a, b), c) == mul(a, mul(b, c))

    def test_commutativity_add(self, rng):
        for _ in range(20):
            a, b = rand_element(rng), rand_element(rng)
            assert add(a, b) == add(b, a)

    def test_commutativity_mul(self, rng):
        for _ in range(20):
            a, b = rand_element(rng), rand_element(rng)
            assert mul(a, b) == mul(b, a)

    def test_distributivity(self, rng):
        for _ in range(20):
            a, b, c = [rand_element(rng) for _ in range(3)]
            # a * (b + c) == a*b + a*c
            assert mul(a, add(b, c)) == add(mul(a, b), mul(a, c))

    def test_additive_identity(self, sample_elements):
        for a in sample_elements:
            assert add(a, 0) == a
            assert add(0, a) == a

    def test_multiplicative_identity(self, sample_elements):
        for a in sample_elements:
            assert mul(a, 1) == a
            assert mul(1, a) == a

    def test_additive_inverse(self, sample_elements):
        for a in sample_elements:
            assert add(a, neg(a)) == 0

    def test_multiplicative_inverse(self, rng):
        for _ in range(20):
            a = rand_element(rng)
            if a == 0:
                continue
            assert mul(a, inv(a)) == 1

    def test_inverse_of_zero_raises(self):
        with pytest.raises(ZeroDivisionError):
            inv(0)


class TestArithmetic:
    """Concrete arithmetic tests."""

    def test_add_basic(self):
        assert add(3, 5) == 8
        assert add(M61 - 1, 1) == 0  # wraparound
        assert add(M61 - 1, 2) == 1

    def test_sub_basic(self):
        assert sub(5, 3) == 2
        assert sub(0, 1) == M61 - 1  # wraparound
        assert sub(3, 5) == M61 - 2

    def test_mul_basic(self):
        assert mul(2, 3) == 6
        assert mul(M61 - 1, 2) == M61 - 2  # (-1)*2 = -2

    def test_neg_basic(self):
        assert neg(0) == 0
        assert neg(1) == M61 - 1
        assert neg(M61 - 1) == 1

    def test_div_basic(self):
        assert div(6, 3) == 2
        assert div(1, 1) == 1

    def test_large_multiply_no_overflow(self):
        """M61-1 * M61-1 should reduce correctly."""
        a = M61 - 1  # This is -1 mod M61
        assert mul(a, a) == 1  # (-1)*(-1) = 1


class TestPolynomial:
    """Polynomial evaluation."""

    def test_constant_polynomial(self):
        assert poly_eval([42], 7) == 42

    def test_linear_polynomial(self):
        # 3x + 5 at x=2 -> 11
        assert poly_eval([3, 5], 2) == 11

    def test_quadratic_polynomial(self):
        # 2x^2 + 3x + 1 at x=4 -> 32+12+1 = 45
        assert poly_eval([2, 3, 1], 4) == 45

    def test_poly_eval_low_matches(self):
        # coeffs_low = [a0, a1, a2] = [1, 3, 2] -> 1 + 3x + 2x^2
        # At x=4: 1 + 12 + 32 = 45
        assert poly_eval_low([1, 3, 2], 4) == 45

    def test_manual_polynomial(self):
        # f(x) = x^3 + 2x + 7, at x=3: 27+6+7=40
        assert poly_eval([1, 0, 2, 7], 3) == 40

    def test_polynomial_at_zero(self):
        # f(0) = constant term
        assert poly_eval([5, 3, 7], 0) == 7

    def test_polynomial_modular(self):
        # Large coefficients reduce correctly
        c = M61 - 1  # = -1
        # f(x) = (-1)x + 1, at x=1: -1+1=0
        assert poly_eval([c, 1], 1) == 0


class TestLagrange:
    """Lagrange interpolation."""

    def test_interpolate_two_points(self):
        # Line through (1,3) and (2,7): y = 4x - 1
        points = [(1, 3), (2, 7)]
        # At x=3: 4*3-1=11
        assert lagrange_interpolate(points, 3) == 11
        # At x=0: -1 mod M61 = M61-1
        assert lagrange_interpolate(points, 0) == M61 - 1

    def test_interpolate_recovers_points(self, rng):
        """Interpolation through the given points recovers those values."""
        xs = [rand_element(rng) for _ in range(5)]
        ys = [rand_element(rng) for _ in range(5)]
        points = list(zip(xs, ys))
        for x, y in points:
            assert lagrange_interpolate(points, x) == y

    def test_lagrange_roundtrip_polynomial(self, rng):
        """Evaluate a random polynomial at N points, interpolate, recover."""
        degree = 4
        coeffs = [rand_element(rng) for _ in range(degree + 1)]
        xs = [rand_element(rng) for _ in range(degree + 1)]
        points = [(x, poly_eval(coeffs, x)) for x in xs]
        # Evaluate interpolant at a new point
        test_x = rand_element(rng)
        expected = poly_eval(coeffs, test_x)
        actual = lagrange_interpolate(points, test_x)
        assert actual == expected

    def test_lagrange_basis_at_zero(self):
        """Basis coefficients at 0 sum Lagrange-weighted shares to f(0)."""
        # f(x) = 7x + 42, so f(0) = 42
        # Shares at x=1,2,3: f(1)=49, f(2)=56, f(3)=63
        xs = [1, 2, 3]
        ys = [49, 56, 63]
        result = 0
        for i in range(3):
            L_i = lagrange_basis_at_zero(xs, i)
            result = add(result, mul(ys[i], L_i))
        assert result == 42


class TestRandElement:
    """Random element generation."""

    def test_in_range(self, rng):
        for _ in range(100):
            r = rand_element(rng)
            assert 0 <= r < M61

    def test_not_constant(self, rng):
        """Different calls produce different values (with high probability)."""
        values = {rand_element(rng) for _ in range(20)}
        assert len(values) > 1
