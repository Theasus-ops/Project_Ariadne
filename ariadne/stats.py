"""Small statistics helpers for honest error-rate reporting.

A point estimate like "0% false positives" is not an honest claim on a sample of
60 — the true rate could be several percent and you'd still expect to see zero. A
measured error rate is only credible with an interval and a sample size attached.

The **Wilson score interval** is the right tool for a binomial proportion: unlike
the naive normal approximation it stays inside [0, 1] and behaves sensibly at the
extremes (0 or 100% observed) and for small n — exactly the regimes a forensic
validation corpus lives in.

Pure functions, no dependencies, deterministic — so the numbers in a published
validation report can be reproduced exactly.
"""

from __future__ import annotations

import math

# z for common two-sided confidence levels.
Z = {0.90: 1.6448536269514722, 0.95: 1.959963984540054, 0.99: 2.5758293035489004}


def wilson_interval(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Wilson score confidence interval for a binomial proportion k/n.

    Returns (low, high) as fractions in [0, 1]. With no observations (n == 0) the
    interval is the whole range (0, 1) — no data, no claim.
    """
    if n <= 0:
        return (0.0, 1.0)
    if k < 0 or k > n:
        raise ValueError(f"k={k} out of range for n={n}")
    z = Z.get(round(confidence, 2), 1.959963984540054)
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return (max(0.0, center - margin), min(1.0, center + margin))


def rate_ci(k: int, n: int, confidence: float = 0.95) -> dict:
    """A proportion with its Wilson interval, ready to serialise into a report."""
    lo, hi = wilson_interval(k, n, confidence)
    return {
        "count": k,
        "n": n,
        "rate": (k / n) if n else 0.0,
        "ci_low": lo,
        "ci_high": hi,
        "confidence": confidence,
    }


def format_pct_ci(k: int, n: int, confidence: float = 0.95) -> str:
    """Human string, e.g. '0.0% (95% CI 0.0–6.0%, n=60)'."""
    d = rate_ci(k, n, confidence)
    pct = int(round(confidence * 100))
    return (
        f"{d['rate'] * 100:.1f}% ({pct}% CI {d['ci_low'] * 100:.1f}"
        f"–{d['ci_high'] * 100:.1f}%, n={n})"
    )
