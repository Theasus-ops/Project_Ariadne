"""Tests for the Wilson-interval statistics used in error-rate reporting."""

import math

from ariadne.stats import format_pct_ci, rate_ci, wilson_interval


def test_no_observations_is_full_range():
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_zero_successes_lower_bound_is_zero_upper_is_positive():
    lo, hi = wilson_interval(0, 60, 0.95)
    assert lo == 0.0
    # The honest point: 0/60 does NOT prove a 0% rate — the CI reaches ~6%.
    assert math.isclose(hi, 0.0602, abs_tol=0.002)


def test_all_successes_upper_bound_is_one():
    lo, hi = wilson_interval(100, 100, 0.95)
    assert hi == 1.0
    assert lo < 1.0 and lo > 0.94   # tight but not certain


def test_interval_brackets_point_estimate():
    for k, n in [(1, 100), (25, 50), (3, 7), (999, 1000)]:
        lo, hi = wilson_interval(k, n)
        assert 0.0 <= lo <= k / n <= hi <= 1.0


def test_symmetry_of_complement():
    lo, hi = wilson_interval(10, 100)
    lo2, hi2 = wilson_interval(90, 100)
    assert math.isclose(lo, 1 - hi2, abs_tol=1e-9)
    assert math.isclose(hi, 1 - lo2, abs_tol=1e-9)


def test_more_data_tightens_the_interval():
    _, hi_small = wilson_interval(0, 10)
    _, hi_big = wilson_interval(0, 1000)
    assert hi_big < hi_small   # same 0% observed, far tighter bound with more data


def test_confidence_level_widens_interval():
    lo90, hi90 = wilson_interval(5, 100, 0.90)
    lo99, hi99 = wilson_interval(5, 100, 0.99)
    assert lo99 < lo90 and hi99 > hi90


def test_rate_ci_payload():
    d = rate_ci(3, 60)
    assert d["count"] == 3 and d["n"] == 60 and math.isclose(d["rate"], 0.05)
    assert d["ci_low"] < 0.05 < d["ci_high"]


def test_format_pct_ci_string():
    s = format_pct_ci(0, 60)
    assert s.startswith("0.0% (95% CI 0.0–") and "n=60" in s
