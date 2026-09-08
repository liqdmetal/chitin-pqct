"""Conservative statistical-distance bounds for finite Gaussian experiments.

This module proves only distributional facts about the finite-support reference
samplers used by the research harness. It does not assert that the harness
implements Gao's exact D_1/D_2/D_3 conventions, and it does not prove SHVZK,
soundness, or Fiat--Shamir security.

All bounds use total variation distance. A bound returned by this module is an
upper bound under ideal real-arithmetic sampling; the Decimal inverse-CDF
implementation needs a separate numerical-rounding audit.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Iterable, Sequence


class StatisticalDistanceError(ValueError):
    """Invalid statistical-distance input."""


def _validate_profile(sigma: Decimal, tail: int) -> None:
    if sigma <= 0:
        raise StatisticalDistanceError("sigma must be positive")
    if tail < 0:
        raise StatisticalDistanceError("tail must be nonnegative")


def _weight(sigma: Decimal, value: int) -> Decimal:
    return (-(Decimal(value * value) / (Decimal(2) * sigma * sigma))).exp()


def finite_normalizer(sigma: Decimal, tail: int) -> Decimal:
    """Return the unnormalised mass on ``[-tail, tail]``."""
    _validate_profile(sigma, tail)
    return sum((_weight(sigma, value) for value in range(-tail, tail + 1)), Decimal(0))


def omitted_unnormalized_mass_upper_bound(sigma: Decimal, tail: int) -> Decimal:
    """Upper-bound the two-sided unnormalised mass outside finite support.

    For ``t = tail + 1``, the positive tail is bounded by

        exp(-t^2/(2*sigma^2)) / (1 - exp(-(2*t+1)/(2*sigma^2))).

    This is a discrete geometric bound, not a continuous Gaussian
    approximation. It is conservative and uses no floating-point ``erfc``.
    """
    _validate_profile(sigma, tail)
    first = tail + 1
    first_weight = _weight(sigma, first)
    ratio = (-(Decimal(2 * first + 1) / (Decimal(2) * sigma * sigma))).exp()
    return (Decimal(2) * first_weight) / (Decimal(1) - ratio)


def truncation_tv_upper_bound(sigma: Decimal, tail: int) -> Decimal:
    """Bound TV between infinite and renormalized finite discrete Gaussians.

    The exact TV distance for truncation is the omitted infinite-support mass.
    If ``U`` bounds the omitted unnormalised mass and ``Z_T`` is the retained
    unnormalised mass, then TV is at most ``U/(Z_T+U)``.
    """
    retained = finite_normalizer(sigma, tail)
    omitted = omitted_unnormalized_mass_upper_bound(sigma, tail)
    return min(Decimal(1), omitted / (retained + omitted))


def product_tv_union_bound(component_bounds: Iterable[Decimal]) -> Decimal:
    """Use the coupling/union bound for independent component distributions."""
    total = Decimal(0)
    for value in component_bounds:
        if value < 0 or value > 1:
            raise StatisticalDistanceError("component TV bounds must be in [0, 1]")
        total += value
    return min(Decimal(1), total)


def gaussian_product_tv_upper_bound(
    sigma: Decimal,
    tail: int,
    coordinate_count: int,
) -> Decimal:
    """Bound TV for ``coordinate_count`` independent truncated coordinates."""
    if coordinate_count < 0:
        raise StatisticalDistanceError("coordinate count must be nonnegative")
    return product_tv_union_bound(
        truncation_tv_upper_bound(sigma, tail) for _ in range(coordinate_count)
    )


def inverse_cdf_grid_tv_upper_bound(support_size: int, uniform_bits: int = 256) -> Decimal:
    """Bound ideal inverse-CDF grid quantization error.

    Convention: the sampler draws one integer ``U`` uniformly from
    ``{0,...,M-1}``, with ``M=2**uniform_bits``, uses ``u=U/M``, and returns the
    first support point whose exact cumulative mass is strictly greater than
    ``u``. Under this fixed floor-grid convention, replacing continuous
    ``u~Uniform[0,1)`` by the grid changes each CDF-bin probability by at most
    one grid cell; ``support_size/M`` is a conservative union bound. This does
    not include Decimal exponent, summation, or comparison rounding, seed/XOF
    modelling, or rejection conditioning.
    """
    if support_size <= 0 or uniform_bits <= 0:
        raise StatisticalDistanceError("support size and uniform bits must be positive")
    return min(Decimal(1), Decimal(support_size) / Decimal(1 << uniform_bits))


def conditioned_tv_upper_bound(base_tv: Decimal, acceptance_lower_bound: Decimal) -> Decimal:
    """Bound TV after conditioning both laws on an event.

    If the unconditioned laws have TV at most ``base_tv`` and both acceptance
    probabilities are at least ``acceptance_lower_bound``, the conditioned TV
    is at most ``2*base_tv/acceptance_lower_bound``. This intentionally loose
    bound is safe for rejection experiments; it says nothing if the acceptance
    lower bound is absent or if the two samplers use different events.
    """
    if base_tv < 0 or base_tv > 1:
        raise StatisticalDistanceError("base TV must be in [0, 1]")
    if acceptance_lower_bound <= 0 or acceptance_lower_bound > 1:
        raise StatisticalDistanceError("acceptance lower bound must be in (0, 1]")
    return min(Decimal(1), (Decimal(2) * base_tv) / acceptance_lower_bound)


__all__ = [
    "StatisticalDistanceError",
    "conditioned_tv_upper_bound",
    "finite_normalizer",
    "gaussian_product_tv_upper_bound",
    "inverse_cdf_grid_tv_upper_bound",
    "omitted_unnormalized_mass_upper_bound",
    "product_tv_union_bound",
    "truncation_tv_upper_bound",
]
