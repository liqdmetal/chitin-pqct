"""Reference rejection-sampling mechanics for lattice-style transcripts.

This module contains the distribution-independent acceptance equation used by
Lyubashevsky-style rejection sampling. It deliberately does not claim to
implement the paper's exact discrete Gaussian parameterization.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Sequence


class RejectionSamplingError(ValueError):
    """Raised when a rejection-sampling input is invalid."""


def squared_norm(values: Sequence[int]) -> int:
    """Return the exact integer Euclidean squared norm."""
    result = 0
    for value in values:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("norm coordinates must be integers")
        result += value * value
    return result


def log_acceptance_ratio(
    response: Sequence[int],
    shift: Sequence[int],
    sigma: float,
    majorant: float,
) -> float:
    """Return log(q(response)/[M*q(response-shift)]).

    For a discrete-Gaussian-shaped density q(v) proportional to
    exp(-||v||^2/(2*sigma^2)), this is

        (||response-shift||^2 - ||response||^2)/(2*sigma^2) - log(M).

    The caller must choose a majorant M that is valid for the full supported
    message/mask domain. This function checks only the supplied point.
    """
    if len(response) != len(shift) or not response:
        raise RejectionSamplingError("response and shift dimensions must match")
    if not math.isfinite(sigma) or sigma <= 0:
        raise RejectionSamplingError("sigma must be finite and positive")
    if not math.isfinite(majorant) or majorant < 1:
        raise RejectionSamplingError("majorant must be finite and at least one")
    residual = tuple(a - b for a, b in zip(response, shift))
    return (squared_norm(residual) - squared_norm(response)) / (2.0 * sigma * sigma) - math.log(majorant)


def acceptance_probability(
    response: Sequence[int],
    shift: Sequence[int],
    sigma: float,
    majorant: float,
) -> float:
    """Return the rejection-sampling acceptance probability in [0, 1]."""
    log_probability = log_acceptance_ratio(response, shift, sigma, majorant)
    if log_probability > 1e-12:
        raise RejectionSamplingError("majorant is too small for this response")
    return math.exp(log_probability)


def accepts(
    response: Sequence[int],
    shift: Sequence[int],
    sigma: float,
    majorant: float,
    uniform_value: float,
) -> bool:
    """Apply one explicitly supplied uniform random decision."""
    if not math.isfinite(uniform_value) or not 0 <= uniform_value < 1:
        raise RejectionSamplingError("uniform decision must lie in [0, 1)")
    return uniform_value < acceptance_probability(response, shift, sigma, majorant)


@dataclass(frozen=True)
class RejectionSample:
    response: tuple[int, ...]
    shift: tuple[int, ...]
    acceptance_probability: float


def accept_candidate(
    mask: Sequence[int],
    shift: Sequence[int],
    sigma: float,
    majorant: float,
    uniform_value: float,
) -> RejectionSample | None:
    """Accept one candidate mask or return None.

    The response is `mask + shift`, matching the protocol notation `f = d + m`.
    """
    if len(mask) != len(shift) or not mask:
        raise RejectionSamplingError("mask and shift dimensions must match")
    response = tuple(a + b for a, b in zip(mask, shift))
    probability = acceptance_probability(response, shift, sigma, majorant)
    if not accepts(response, shift, sigma, majorant, uniform_value):
        return None
    return RejectionSample(response, tuple(shift), probability)
