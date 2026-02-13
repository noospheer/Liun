"""Curve fitting and extrapolation for efficiency analysis.

Fits measured data to theoretical complexity models:
- DKG: O(N^2)
- Signing: O(N)
- PageRank: O(N * E * iter) ≈ O(N^2 * log(N))
"""

import math


def fit_power_law(ns: list, values: list) -> dict:
    """Fit values = a * n^b using log-linear regression.

    Returns: {'a': float, 'b': float, 'r_squared': float}
    """
    if len(ns) < 2 or len(values) < 2:
        return {'a': 0, 'b': 0, 'r_squared': 0}

    # Filter out zeros
    pairs = [(n, v) for n, v in zip(ns, values) if n > 0 and v > 0]
    if len(pairs) < 2:
        return {'a': 0, 'b': 0, 'r_squared': 0}

    log_n = [math.log(p[0]) for p in pairs]
    log_v = [math.log(p[1]) for p in pairs]

    n = len(log_n)
    sum_x = sum(log_n)
    sum_y = sum(log_v)
    sum_xy = sum(x * y for x, y in zip(log_n, log_v))
    sum_x2 = sum(x * x for x in log_n)

    denom = n * sum_x2 - sum_x * sum_x
    if abs(denom) < 1e-15:
        return {'a': 0, 'b': 0, 'r_squared': 0}

    b = (n * sum_xy - sum_x * sum_y) / denom
    log_a = (sum_y - b * sum_x) / n
    a = math.exp(log_a)

    # R-squared
    mean_y = sum_y / n
    ss_tot = sum((y - mean_y) ** 2 for y in log_v)
    ss_res = sum((y - (log_a + b * x)) ** 2 for x, y in zip(log_n, log_v))
    r_squared = 1 - ss_res / ss_tot if ss_tot > 0 else 0

    return {'a': a, 'b': b, 'r_squared': r_squared}


def fit_quadratic(ns: list, values: list) -> dict:
    """Fit values = a * n^2 + b * n + c.

    Returns: {'a': float, 'b': float, 'c': float}
    """
    if len(ns) < 3:
        return {'a': 0, 'b': 0, 'c': 0}

    # Least squares: minimize ||Ax - v||^2 where A = [n^2, n, 1]
    n = len(ns)
    # Using normal equations (sufficient for small n)
    A = [[ni ** 2, ni, 1] for ni in ns]
    AT = list(zip(*A))
    ATA = [[sum(r * c for r, c in zip(row, col))
            for col in AT] for row in AT]
    ATv = [sum(r * v for r, v in zip(row, values)) for row in AT]

    # Solve 3x3 system (Cramer's rule)
    det = _det3(ATA)
    if abs(det) < 1e-15:
        return {'a': 0, 'b': 0, 'c': 0}

    a = _det3(_replace_col(ATA, ATv, 0)) / det
    b = _det3(_replace_col(ATA, ATv, 1)) / det
    c = _det3(_replace_col(ATA, ATv, 2)) / det

    return {'a': a, 'b': b, 'c': c}


def _det3(m):
    """Determinant of 3x3 matrix."""
    return (m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
            - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
            + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]))


def _replace_col(m, v, col):
    """Replace column col of matrix m with vector v."""
    result = [list(row) for row in m]
    for i in range(len(result)):
        result[i][col] = v[i]
    return result


def extrapolate_power(fit: dict, target_n: int) -> float:
    """Extrapolate using power law: a * n^b."""
    return fit['a'] * (target_n ** fit['b'])


def extrapolate_quadratic(fit: dict, target_n: int) -> float:
    """Extrapolate using quadratic: a*n^2 + b*n + c."""
    return fit['a'] * target_n ** 2 + fit['b'] * target_n + fit['c']


class EfficiencyAnalyzer:
    """Analyzes efficiency scaling from measurements."""

    def __init__(self, collector=None):
        self.collector = collector
        self.fits: dict[str, dict] = {}

    def analyze(self, name: str, ns: list = None, values: list = None) -> dict:
        """Analyze scaling for a named metric.

        Uses collector data if ns/values not provided.
        """
        if ns is None or values is None:
            if self.collector is None:
                raise ValueError("No data source")
            series = self.collector.get_series(name)
            ns = series['n']
            values = series['time_s']

        power_fit = fit_power_law(ns, values)
        quad_fit = fit_quadratic(ns, values) if len(ns) >= 3 else None

        result = {
            'power_fit': power_fit,
            'quadratic_fit': quad_fit,
            'measured_n': ns,
            'measured_values': values,
        }
        self.fits[name] = result
        return result

    def extrapolate(self, name: str, target_ns: list) -> dict:
        """Extrapolate to target network sizes."""
        if name not in self.fits:
            raise ValueError(f"No fit for {name}")

        fit = self.fits[name]
        power = fit['power_fit']

        return {
            n: extrapolate_power(power, n)
            for n in target_ns
        }
