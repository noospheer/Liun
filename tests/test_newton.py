"""Tests for Newton interpolation (optimized path)."""

import random
import pytest
from liun.gf61 import (
    M61, rand_element, rand_nonzero,
    newton_coefficients, newton_eval, InterpolatingPoly,
    lagrange_interpolate, poly_eval_low,
)


class TestNewtonBasic:

    def test_two_points(self):
        """Newton interpolation through 2 points matches Lagrange."""
        points = [(1, 3), (2, 7)]
        xs, coeffs = newton_coefficients(points)
        # At x=3: line through (1,3),(2,7) => y=4*3-1=11
        assert newton_eval(xs, coeffs, 3) == 11
        assert newton_eval(xs, coeffs, 0) == M61 - 1  # -1 mod M61

    def test_matches_lagrange(self, rng):
        """Newton and Lagrange produce identical results."""
        for degree in [2, 5, 10, 20]:
            coeffs = [rand_element(rng) for _ in range(degree + 1)]
            xs = [rand_nonzero(rng) for _ in range(degree + 1)]
            points = [(x, poly_eval_low(coeffs, x)) for x in xs]

            xs_n, coeffs_n = newton_coefficients(points)
            for _ in range(5):
                t = rand_element(rng)
                lag = lagrange_interpolate(points, t)
                newt = newton_eval(xs_n, coeffs_n, t)
                assert lag == newt

    def test_interpolating_poly_class(self, rng):
        """InterpolatingPoly evaluates correctly."""
        degree = 8
        coeffs = [rand_element(rng) for _ in range(degree + 1)]
        xs = [rand_nonzero(rng) for _ in range(degree + 1)]
        points = [(x, poly_eval_low(coeffs, x)) for x in xs]

        poly = InterpolatingPoly(points)
        for x, y in points:
            assert poly.eval_at(x) == y

        # At new points
        for _ in range(10):
            t = rand_element(rng)
            expected = poly_eval_low(coeffs, t)
            assert poly.eval_at(t) == expected

    def test_single_point(self):
        """Degenerate case: 1 point => constant polynomial."""
        points = [(5, 42)]
        poly = InterpolatingPoly(points)
        assert poly.eval_at(5) == 42
        assert poly.eval_at(0) == 42  # constant

    def test_large_degree(self, rng):
        """Newton works for degree 50 polynomial."""
        degree = 50
        coeffs = [rand_element(rng) for _ in range(degree + 1)]
        xs = list(range(1, degree + 2))
        points = [(x, poly_eval_low(coeffs, x)) for x in xs]

        poly = InterpolatingPoly(points)
        test_x = rand_element(rng)
        assert poly.eval_at(test_x) == poly_eval_low(coeffs, test_x)

    def test_newton_at_known_points(self, rng):
        """Newton evaluates correctly at the interpolation points themselves."""
        degree = 15
        points = [(rand_nonzero(rng), rand_element(rng)) for _ in range(degree + 1)]
        poly = InterpolatingPoly(points)
        for x, y in points:
            assert poly.eval_at(x) == y
