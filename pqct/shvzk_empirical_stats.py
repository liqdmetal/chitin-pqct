"""Collision-aware empirical diagnostics for fixed-challenge SHVZK experiments.

These statistics do not replace a proof. They avoid the trivial ``TV=1`` result
caused by serializing high-dimensional continuous-looking responses into exact
histogram bins.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from typing import Iterable, Sequence


class EmpiricalStatsError(ValueError):
    pass


@dataclass(frozen=True)
class CollisionAwareStats:
    samples_left: int
    samples_right: int
    bins: int
    left_distinct: int
    right_distinct: int
    pooled_distinct: int
    exact_histogram_tv: Decimal
    chi_square_distance: Decimal
    collision_probability_left: Decimal
    collision_probability_right: Decimal
    pooled_collision_probability: Decimal
    left_min_entropy_lower_bound: Decimal
    right_min_entropy_lower_bound: Decimal


def _check_samples(values: Sequence[bytes], name: str) -> tuple[bytes, ...]:
    normalized = tuple(values)
    if not normalized:
        raise EmpiricalStatsError(f"{name} sample set cannot be empty")
    return normalized


def _coarsen(value: bytes, prefix_bytes: int) -> bytes:
    if prefix_bytes < 0:
        raise EmpiricalStatsError("prefix_bytes must be nonnegative")
    return value[:prefix_bytes]


def _digest_coarsen(value: bytes, digest_bytes: int) -> bytes:
    if digest_bytes <= 0 or digest_bytes > 32:
        raise EmpiricalStatsError("digest_bytes must be in 1..32")
    return sha256(value).digest()[:digest_bytes]


def _counter_digest(values: Iterable[bytes], digest_bytes: int) -> Counter[bytes]:
    return Counter(_digest_coarsen(value, digest_bytes) for value in values)


def collision_aware_digest_stats(
    left: Sequence[bytes],
    right: Sequence[bytes],
    *,
    digest_bytes: int = 2,
) -> CollisionAwareStats:
    """Compare random digest buckets, reducing serialization-prefix bias."""
    left_values = _check_samples(left, "left")
    right_values = _check_samples(right, "right")
    left_hist = _counter_digest(left_values, digest_bytes)
    right_hist = _counter_digest(right_values, digest_bytes)
    pooled_hist = left_hist + right_hist
    exact_left = Counter(left_values)
    exact_right = Counter(right_values)
    return CollisionAwareStats(
        samples_left=len(left_values),
        samples_right=len(right_values),
        bins=len(set(left_hist) | set(right_hist)),
        left_distinct=len(left_hist),
        right_distinct=len(right_hist),
        pooled_distinct=len(pooled_hist),
        exact_histogram_tv=_tv(exact_left, exact_right),
        chi_square_distance=sum(
            (Decimal(left_hist[key]) - Decimal(right_hist[key])) ** 2
            / Decimal(max(1, left_hist[key] + right_hist[key]))
            for key in set(left_hist) | set(right_hist)
        ),
        collision_probability_left=_collision_probability(left_hist),
        collision_probability_right=_collision_probability(right_hist),
        pooled_collision_probability=_collision_probability(pooled_hist),
        left_min_entropy_lower_bound=_min_entropy_lower_bound(left_hist),
        right_min_entropy_lower_bound=_min_entropy_lower_bound(right_hist),
    )


@dataclass(frozen=True)
class MarginalIntegerStats:
    """Per-coefficient marginal comparison over a small bounded integer support.

    Unlike the full response/transcript tuple (astronomically large support,
    where TV=1 is a birthday-bound artifact), individual scalar coefficients
    of g_i,j / z_g / z_b live in a small bounded range under Gao's claimed
    D_{1,T1} / D_{2,T2} laws, so real collisions occur and a genuine mismatch
    is detectable with a moderate sample count.
    """

    left_count: int
    right_count: int
    left_mean: Decimal
    right_mean: Decimal
    left_variance: Decimal
    right_variance: Decimal
    distinct_values: int
    exact_tv: Decimal


def _int_stats(values: Sequence[int]) -> tuple[Decimal, Decimal]:
    count = len(values)
    if count == 0:
        return Decimal(0), Decimal(0)
    mean = Decimal(sum(values)) / Decimal(count)
    variance = sum((Decimal(v) - mean) ** 2 for v in values) / Decimal(count)
    return mean, variance


def marginal_integer_stats(
    left: Sequence[int],
    right: Sequence[int],
) -> MarginalIntegerStats:
    """Compare two pooled coefficient samples over their exact integer support."""
    if not left or not right:
        raise EmpiricalStatsError("marginal sample sets cannot be empty")
    left_hist = Counter(left)
    right_hist = Counter(right)
    left_mean, left_variance = _int_stats(left)
    right_mean, right_variance = _int_stats(right)
    return MarginalIntegerStats(
        left_count=len(left),
        right_count=len(right),
        left_mean=left_mean,
        right_mean=right_mean,
        left_variance=left_variance,
        right_variance=right_variance,
        distinct_values=len(set(left_hist) | set(right_hist)),
        exact_tv=_tv(left_hist, right_hist),
    )


def _counter(values: Iterable[bytes], prefix_bytes: int) -> Counter[bytes]:
    return Counter(_coarsen(value, prefix_bytes) for value in values)


def _tv(left: Counter[bytes], right: Counter[bytes]) -> Decimal:
    n_left = sum(left.values())
    n_right = sum(right.values())
    if n_left <= 0 or n_right <= 0:
        raise EmpiricalStatsError("histograms cannot be empty")
    keys = set(left) | set(right)
    return min(
        Decimal(1),
        sum(
            abs(Decimal(left[key]) / n_left - Decimal(right[key]) / n_right) / 2
            for key in keys
        ),
    )


def _collision_probability(counter: Counter[bytes]) -> Decimal:
    total = sum(counter.values())
    if total < 2:
        return Decimal(0)
    numerator = sum(value * (value - 1) for value in counter.values())
    return Decimal(numerator) / Decimal(total * (total - 1))


def _min_entropy_lower_bound(counter: Counter[bytes]) -> Decimal:
    total = sum(counter.values())
    maximum = max(counter.values())
    return -(Decimal(maximum) / Decimal(total)).ln() / Decimal(2).ln()


def collision_aware_stats(
    left: Sequence[bytes],
    right: Sequence[bytes],
    *,
    prefix_bytes: int = 2,
) -> CollisionAwareStats:
    """Compute bounded, explicitly binned diagnostics for two sample sets."""
    left_values = _check_samples(left, "left")
    right_values = _check_samples(right, "right")
    left_hist = _counter(left_values, prefix_bytes)
    right_hist = _counter(right_values, prefix_bytes)
    pooled_hist = left_hist + right_hist
    exact_left = Counter(left_values)
    exact_right = Counter(right_values)
    return CollisionAwareStats(
        samples_left=len(left_values),
        samples_right=len(right_values),
        bins=len(set(left_hist) | set(right_hist)),
        left_distinct=len(left_hist),
        right_distinct=len(right_hist),
        pooled_distinct=len(pooled_hist),
        exact_histogram_tv=_tv(exact_left, exact_right),
        chi_square_distance=sum(
            (Decimal(left_hist[key]) - Decimal(right_hist[key])) ** 2
            / Decimal(max(1, left_hist[key] + right_hist[key]))
            for key in set(left_hist) | set(right_hist)
        ),
        collision_probability_left=_collision_probability(left_hist),
        collision_probability_right=_collision_probability(right_hist),
        pooled_collision_probability=_collision_probability(pooled_hist),
        left_min_entropy_lower_bound=_min_entropy_lower_bound(left_hist),
        right_min_entropy_lower_bound=_min_entropy_lower_bound(right_hist),
    )


__all__ = [
    "CollisionAwareStats",
    "EmpiricalStatsError",
    "MarginalIntegerStats",
    "collision_aware_digest_stats",
    "collision_aware_stats",
    "marginal_integer_stats",
]
