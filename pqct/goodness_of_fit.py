"""Pure-stdlib chi-square goodness-of-fit test (no scipy/numpy dependency).

Tests whether an empirical sample matches a CLAIMED discrete distribution --
e.g. whether honest/simulator marginal coefficients actually follow the
paper's stated D_sigma law, not just whether they match each other (which
the marginal TV comparison in shvzk_empirical_stats.py already checks).

The regularized incomplete gamma function is implemented from a standard
series/continued-fraction algorithm (Numerical Recipes 6.2), independently
validated against scipy.stats.chi2 in tests/test_goodness_of_fit.py (scipy
is a TEST ORACLE only; pqct itself declares zero dependencies).
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from math import exp, lgamma, log
from typing import Mapping, Sequence


class GoodnessOfFitError(ValueError):
    """Invalid goodness-of-fit input."""


_ITMAX = 500
_EPS = 1e-14
_TINY = 1e-290


def _gammainc_series(a: float, x: float) -> float:
    """Regularized lower incomplete gamma P(a,x) via power series (x<a+1)."""
    if x < 0:
        raise GoodnessOfFitError("x must be nonnegative")
    if x == 0:
        return 0.0
    log_prefactor = -x + a * log(x) - lgamma(a)
    term = 1.0 / a
    total = term
    n = a
    for _ in range(_ITMAX):
        n += 1.0
        term *= x / n
        total += term
        if abs(term) < abs(total) * _EPS:
            break
    result = total * exp(log_prefactor)
    return min(1.0, max(0.0, result))


def _gammaincc_cf(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a,x) via continued fraction (x>=a+1)."""
    if x < 0:
        raise GoodnessOfFitError("x must be nonnegative")
    log_prefactor = -x + a * log(x) - lgamma(a)
    b = x + 1.0 - a
    c = 1.0 / _TINY
    d = 1.0 / b
    h = d
    for i in range(1, _ITMAX + 1):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < _TINY:
            d = _TINY
        c = b + an / c
        if abs(c) < _TINY:
            c = _TINY
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            break
    result = exp(log_prefactor) * h
    return min(1.0, max(0.0, result))


def regularized_gamma_q(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a,x) = 1 - P(a,x)."""
    if a <= 0:
        raise GoodnessOfFitError("a must be positive")
    if x < 0:
        raise GoodnessOfFitError("x must be nonnegative")
    if x == 0:
        return 1.0
    if x < a + 1.0:
        return 1.0 - _gammainc_series(a, x)
    return _gammaincc_cf(a, x)


def chi_square_p_value(statistic: float, degrees_of_freedom: int) -> float:
    """P(X >= statistic) for X ~ chi-square(degrees_of_freedom).

    This is Q(k/2, statistic/2), the regularized upper incomplete gamma
    function -- the standard closed form for the chi-square survival
    function (see e.g. Abramowitz & Stegun 26.4.19, or Numerical Recipes
    section 6.2). Cross-checked against scipy.stats.chi2.sf in
    tests/test_goodness_of_fit.py (scipy used only as a test oracle).
    """
    if degrees_of_freedom <= 0:
        raise GoodnessOfFitError("degrees_of_freedom must be positive")
    if statistic < 0:
        raise GoodnessOfFitError("statistic must be nonnegative")
    return regularized_gamma_q(degrees_of_freedom / 2.0, statistic / 2.0)


@dataclass(frozen=True)
class ChiSquareResult:
    statistic: float
    degrees_of_freedom: int
    p_value: float
    bins_used: int
    total_samples: int
    merged_low_expected_bins: int


def chi_square_goodness_of_fit(
    observed_counts: Mapping[int, int],
    expected_probabilities: Mapping[int, Decimal],
    *,
    min_expected: float = 5.0,
) -> ChiSquareResult:
    """Test whether observed_counts follows expected_probabilities.

    Bins with expected count below min_expected are merged into adjacent
    bins (standard chi-square practice; Cochran's rule of thumb) so the
    asymptotic chi-square approximation stays valid. Any support value in
    observed_counts missing from expected_probabilities is an error --
    the caller's claimed distribution must cover the full observed
    support, or the test is not well-posed.
    """
    if min_expected <= 0:
        raise GoodnessOfFitError("min_expected must be positive")
    total = sum(observed_counts.values())
    if total <= 0:
        raise GoodnessOfFitError("observed_counts must have positive total")
    prob_total = sum(expected_probabilities.values())
    if abs(prob_total - 1) > Decimal("1e-9"):
        raise GoodnessOfFitError(
            f"expected_probabilities must sum to 1, got {prob_total}"
        )
    missing = set(observed_counts) - set(expected_probabilities)
    if missing:
        raise GoodnessOfFitError(
            f"expected_probabilities missing support values: {sorted(missing)}"
        )
    support = sorted(expected_probabilities)
    observed = [observed_counts.get(value, 0) for value in support]
    expected = [float(expected_probabilities[value]) * total for value in support]

    merged_observed: list[float] = []
    merged_expected: list[float] = []
    merged_count = 0
    pending_observed = 0.0
    pending_expected = 0.0
    for obs, exp_count in zip(observed, expected):
        pending_observed += obs
        pending_expected += exp_count
        if pending_expected >= min_expected:
            merged_observed.append(pending_observed)
            merged_expected.append(pending_expected)
            pending_observed = 0.0
            pending_expected = 0.0
        else:
            merged_count += 1
    if pending_expected > 0:
        if merged_expected:
            merged_observed[-1] += pending_observed
            merged_expected[-1] += pending_expected
            merged_count += 1
        else:
            merged_observed.append(pending_observed)
            merged_expected.append(pending_expected)
    if len(merged_expected) < 2:
        raise GoodnessOfFitError(
            "fewer than 2 usable bins after merging low-expected-count "
            "bins; increase sample size or widen expected support"
        )
    statistic = sum(
        (obs - exp_count) ** 2 / exp_count
        for obs, exp_count in zip(merged_observed, merged_expected)
    )
    degrees_of_freedom = len(merged_expected) - 1
    p_value = chi_square_p_value(statistic, degrees_of_freedom)
    return ChiSquareResult(
        statistic=statistic,
        degrees_of_freedom=degrees_of_freedom,
        p_value=p_value,
        bins_used=len(merged_expected),
        total_samples=total,
        merged_low_expected_bins=merged_count,
    )


__all__ = [
    "ChiSquareResult",
    "GoodnessOfFitError",
    "chi_square_goodness_of_fit",
    "chi_square_p_value",
    "regularized_gamma_q",
]
