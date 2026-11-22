"""Binomial confidence intervals for evaluation rates (#175).

Why: lab datasets have a handful of sessions per class (lab-mini: 3 benign, 2 AI), so a point estimate such as
"FPR 0 %" or "AI recall 100 %" says almost nothing on its own — 0/3 is compatible with a true rate of 70 %.
Every rate in metrics.json therefore carries its numerator, denominator and an interval.

* :func:`clopper_pearson` — exact (conservative) two-sided interval from the binomial distribution. This is the
  one reported (``method = "clopper-pearson"``): it never under-covers, which is the safe side for a security
  product claim.
* :func:`wilson` — Wilson score interval, narrower and the usual choice for display; kept for comparison.

Both are implemented here (no SciPy dependency). The binomial CDF is summed in log space with ``lgamma`` so large
``n`` does not overflow; Clopper–Pearson bounds are found by bisection on that CDF.

Caveat: the binomial model assumes independent trials. Session-level rates are close to that; event-level rates
(event recall / event FPR) are clustered by session, so their intervals are too narrow.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from statistics import NormalDist

DEFAULT_CONFIDENCE = 0.95
# Below this many trials a rate is shown as a reference value only (report.md: 参考値).
MIN_N_FOR_ESTIMATE = 30


def _check(x: int, n: int, confidence: float) -> None:
    if n < 0 or x < 0 or x > n:
        raise ValueError(f"need 0 <= x <= n, got x={x}, n={n}")
    if not 0.0 < confidence < 1.0:
        raise ValueError(f"confidence must be in (0, 1), got {confidence}")


def binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p), computed in log space."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    lp, lq = math.log(p), math.log1p(-p)
    lgn = math.lgamma(n + 1)
    terms = [lgn - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq for i in range(k + 1)]
    top = max(terms)
    return min(1.0, math.exp(top) * math.fsum(math.exp(t - top) for t in terms))


def _bisect_decreasing(
    f_target: float, fn: Callable[[float], float], lo: float = 0.0, hi: float = 1.0
) -> float:
    """Find p in [lo, hi] with fn(p) == f_target for a function decreasing in p."""
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if fn(mid) > f_target:
            lo = mid
        else:
            hi = mid
        if hi - lo < 1e-12:
            break
    return (lo + hi) / 2.0


def clopper_pearson(x: int, n: int, confidence: float = DEFAULT_CONFIDENCE) -> tuple[float, float] | None:
    """Exact two-sided interval: lower solves P(X >= x | p) = a/2, upper solves P(X <= x | p) = a/2."""
    _check(x, n, confidence)
    if n == 0:
        return None
    alpha = 1.0 - confidence
    # P(X >= x | p) = 1 - cdf(x-1) increases with p, i.e. cdf(x-1) decreases with p
    lower = 0.0 if x == 0 else _bisect_decreasing(1.0 - alpha / 2.0, lambda p: binom_cdf(x - 1, n, p))
    upper = 1.0 if x == n else _bisect_decreasing(alpha / 2.0, lambda p: binom_cdf(x, n, p))
    return lower, upper


def wilson(x: int, n: int, confidence: float = DEFAULT_CONFIDENCE) -> tuple[float, float] | None:
    """Wilson score interval (two-sided)."""
    _check(x, n, confidence)
    if n == 0:
        return None
    z = NormalDist().inv_cdf(1.0 - (1.0 - confidence) / 2.0)
    p = x / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1.0 - p) / n + z * z / (4 * n * n)) / denom
    # at x = 0 / x = n the bound is exactly 0 / 1 (avoid 1e-17 rounding residue)
    lower = 0.0 if x == 0 else max(0.0, centre - half)
    upper = 1.0 if x == n else min(1.0, centre + half)
    return lower, upper


def rate_summary(x: int, n: int, *, confidence: float = DEFAULT_CONFIDENCE) -> dict[str, object]:
    """``{"x", "n", "value", "ci_low", "ci_high", "confidence", "method", "reference_only"}`` for metrics.json."""
    ci = clopper_pearson(x, n, confidence)
    return {
        "x": x,
        "n": n,
        "value": round(x / n, 4) if n else None,
        "ci_low": round(ci[0], 4) if ci else None,
        "ci_high": round(ci[1], 4) if ci else None,
        "confidence": confidence,
        "method": "clopper-pearson",
        "reference_only": n < MIN_N_FOR_ESTIMATE,
    }
