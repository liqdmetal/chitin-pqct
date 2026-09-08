"""Reference discrete-Gaussian sampling and calibration helpers.

The paper uses normal/discrete-Gaussian-shaped distributions D_s. This module
uses a finite-support, high-precision reference sampler with injected random
bytes. It is suitable for experiments and empirical calibration only; it is
not constant-time and is not a production cryptographic sampler.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, getcontext
from hashlib import shake_256
from math import exp, sqrt
from typing import Callable, Sequence

getcontext().prec = 80


class GaussianError(ValueError):
    pass


@dataclass(frozen=True)
class GaussianProfile:
    sigma: Decimal
    tail: int

    def __post_init__(self) -> None:
        if self.sigma <= 0 or self.tail < 0:
            raise GaussianError("sigma must be positive and tail nonnegative")

    @property
    def support(self) -> tuple[int, ...]:
        return tuple(range(-self.tail, self.tail + 1))

    @property
    def weights(self) -> tuple[Decimal, ...]:
        denominator = Decimal(2) * self.sigma * self.sigma
        return tuple((-(Decimal(x * x) / denominator)).exp() for x in self.support)

    @property
    def total_weight(self) -> Decimal:
        return sum(self.weights, Decimal(0))

    @property
    def omitted_two_sided_tail_bound(self) -> Decimal:
        # Continuous Gaussian bound; conservative indicator for the finite
        # support approximation, not a proof of statistical distance.
        z = Decimal(self.tail) / self.sigma
        return Decimal(2) * (Decimal("0.5") * (-(z * z) / Decimal(2)).exp())


def _uniform_256(source: Callable[[int], bytes]) -> Decimal:
    raw = source(32)
    if len(raw) != 32:
        raise GaussianError("random source returned wrong length")
    return Decimal(int.from_bytes(raw, "big")) / Decimal(1 << 256)


def sample_truncated(profile: GaussianProfile, source: Callable[[int], bytes]) -> int:
    """Sample from the explicitly normalized finite support by inverse CDF."""
    weights = profile.weights
    total = profile.total_weight
    target = _uniform_256(source) * total
    running = Decimal(0)
    for value, weight in zip(profile.support, weights):
        running += weight
        if target < running:
            return value
    return profile.support[-1]


def shake_source(seed: bytes) -> Callable[[int], bytes]:
    if not seed:
        raise GaussianError("seed cannot be empty")
    counter = 0

    def source(count: int) -> bytes:
        nonlocal counter
        result = shake_256(seed + counter.to_bytes(8, "big")).digest(count)
        counter += 1
        return result

    return source


def empirical_histogram(profile: GaussianProfile, seed: bytes, samples: int) -> dict[int, int]:
    if samples <= 0:
        raise GaussianError("sample count must be positive")
    source = shake_source(seed)
    histogram = {value: 0 for value in profile.support}
    for _ in range(samples):
        histogram[sample_truncated(profile, source)] += 1
    return histogram


def rejection_acceptance(
    response: Sequence[int],
    shift: Sequence[int],
    sigma: float,
    majorant: float,
) -> float:
    """Return the Lyubashevsky-style point acceptance probability."""
    if len(response) != len(shift) or not response:
        raise GaussianError("response and shift dimensions must match")
    if sigma <= 0 or majorant < 1:
        raise GaussianError("invalid rejection parameters")
    residual = sum((a - b) ** 2 for a, b in zip(response, shift))
    observed = sum(a * a for a in response)
    return min(1.0, exp((residual - observed) / (2 * sigma * sigma)) / majorant)
