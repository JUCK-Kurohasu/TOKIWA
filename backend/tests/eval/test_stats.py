"""#175: binomial intervals, checked against closed forms and their defining equations (not memorised tables)."""

from __future__ import annotations

import math
from fractions import Fraction
from statistics import NormalDist

import pytest

from tokiwa.eval.stats import binom_cdf, clopper_pearson, rate_summary, wilson


def _exact_cdf(k: int, n: int, p: float) -> float:
    """Independent check of binom_cdf: plain sum with exact binomial coefficients (small n only)."""
    q = Fraction(p).limit_denominator(10**12)
    return float(sum(math.comb(n, i) * q**i * (1 - q) ** (n - i) for i in range(k + 1)))


@pytest.mark.parametrize("n", [1, 2, 3, 8, 30, 200])
def test_closed_forms_at_the_edges(n: int) -> None:
    # x = 0: upper bound solves (1-p)^n = a/2; x = n: lower bound solves p^n = a/2
    assert clopper_pearson(0, n) == pytest.approx((0.0, 1 - 0.025 ** (1 / n)), abs=1e-9)
    assert clopper_pearson(n, n) == pytest.approx((0.025 ** (1 / n), 1.0), abs=1e-9)


def test_audit_examples() -> None:
    """The audit quoted 0/3 (two-sided upper ~0.708; 0.632 is the one-sided 95 % bound) and 2/2 (0.158-1.0)."""
    lo, hi = clopper_pearson(0, 3)  # type: ignore[misc]
    assert lo == 0.0 and hi == pytest.approx(0.7076, abs=1e-4)
    assert clopper_pearson(0, 3, confidence=0.90)[1] == pytest.approx(1 - 0.05 ** (1 / 3), abs=1e-9)  # type: ignore[index]
    assert clopper_pearson(2, 2)[0] == pytest.approx(0.1581, abs=1e-4)  # type: ignore[index]


@pytest.mark.parametrize(("x", "n"), [(1, 10), (5, 10), (3, 7), (17, 40), (250, 1000)])
def test_bounds_satisfy_their_defining_equations(x: int, n: int) -> None:
    lo, hi = clopper_pearson(x, n)  # type: ignore[misc]
    assert lo < x / n < hi
    assert 1 - binom_cdf(x - 1, n, lo) == pytest.approx(0.025, abs=1e-7)
    assert binom_cdf(x, n, hi) == pytest.approx(0.025, abs=1e-7)


@pytest.mark.parametrize(("x", "n"), [(0, 3), (1, 10), (4, 9), (9, 9), (12, 50)])
def test_symmetry(x: int, n: int) -> None:
    lo, hi = clopper_pearson(x, n)  # type: ignore[misc]
    lo2, hi2 = clopper_pearson(n - x, n)  # type: ignore[misc]
    assert lo == pytest.approx(1 - hi2, abs=1e-9) and hi == pytest.approx(1 - lo2, abs=1e-9)


@pytest.mark.parametrize(("k", "n", "p"), [(0, 5, 0.3), (2, 5, 0.3), (4, 12, 0.5), (7, 20, 0.123)])
def test_binom_cdf_matches_exact_sum(k: int, n: int, p: float) -> None:
    assert binom_cdf(k, n, p) == pytest.approx(_exact_cdf(k, n, p), rel=1e-9)


def test_large_n_does_not_overflow() -> None:
    lo, hi = clopper_pearson(5000, 10000)  # type: ignore[misc]
    assert 0.49 < lo < 0.5 < hi < 0.51
    assert binom_cdf(10, 5000, 0.5) == pytest.approx(0.0, abs=1e-300)


@pytest.mark.parametrize(("x", "n"), [(0, 10), (5, 10), (1, 3), (30, 30)])
def test_wilson_formula(x: int, n: int) -> None:
    z = NormalDist().inv_cdf(0.975)
    p = x / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z / (1 + z * z / n) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    assert wilson(x, n) == pytest.approx((max(0.0, centre - half), min(1.0, centre + half)), abs=1e-12)
    w_lo, w_hi = wilson(x, n)  # type: ignore[misc]
    assert w_lo <= p <= w_hi


def test_rate_summary_and_edge_cases() -> None:
    r = rate_summary(0, 3)
    assert r["x"] == 0 and r["n"] == 3 and r["value"] == 0.0
    assert r["ci_low"] == 0.0 and r["ci_high"] == 0.7076 and r["reference_only"] is True
    assert rate_summary(30, 30)["reference_only"] is False
    empty = rate_summary(0, 0)
    assert empty["value"] is None and empty["ci_low"] is None
    assert clopper_pearson(0, 0) is None and wilson(0, 0) is None
    with pytest.raises(ValueError):
        clopper_pearson(4, 3)
