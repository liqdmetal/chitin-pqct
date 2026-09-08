"""Reference cycle-masking arithmetic from Gao et al. Protocol 2.

This module implements only the exact integer masking identity. It is not a
zero-knowledge proof and does not implement Gao's partially amortized binary
proof, commitment scheme, rejection sampling, or security parameters.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class CycleMask:
    """A mask d with an exact zero weighted sum Σ 2^j d_j."""

    values: tuple[int, ...]
    sampled_values: tuple[int, ...]

    def __post_init__(self) -> None:
        if len(self.values) < 2:
            raise ValueError("cycle mask needs at least two coordinates")
        if len(self.sampled_values) != len(self.values) + 1:
            raise ValueError("sampled mask must have one endpoint beyond derived mask")
        if self.sampled_values[0] != 0 or self.sampled_values[-1] != 0:
            raise ValueError("cycle endpoints must be zero")
        if self.weighted_sum() != 0:
            raise ValueError("cycle mask weighted sum is not zero")

    def weighted_sum(self) -> int:
        return sum((1 << index) * value for index, value in enumerate(self.values))

    def max_abs(self) -> int:
        return max(abs(value) for value in self.values)


def derive_cycle_mask(sampled_values: Sequence[int]) -> CycleMask:
    """Derive d_j = d'_j - 2*d'_(j+1), with d'_0=d'_k=0.

    The returned vector has k coordinates and satisfies exactly:

        Σ_{j=0}^{k-1} 2^j d_j = 0.

    Sampling distribution and rejection sampling are intentionally the caller's
    responsibility; this function performs no cryptographic randomness.
    """
    sampled = tuple(int(value) for value in sampled_values)
    if len(sampled) < 2:
        raise ValueError("at least two sampled coordinates are required")
    if sampled[0] != 0 or sampled[-1] != 0:
        raise ValueError("sampled endpoints must be zero")
    derived = tuple(
        sampled[index] - 2 * sampled[index + 1]
        for index in range(len(sampled) - 1)
    )
    return CycleMask(derived, sampled)


def mask_relation(columns: Sequence[int], challenge: int, mask: CycleMask) -> tuple[int, ...]:
    """Return f_j = challenge*c_j + d_j for an exact relation transcript."""
    if len(columns) != len(mask.values):
        raise ValueError("relation and mask dimensions differ")
    if not isinstance(challenge, int) or isinstance(challenge, bool):
        raise TypeError("challenge must be an integer")
    return tuple(challenge * column + value for column, value in zip(columns, mask.values))


def reconstruct_first_response(response_tail: Sequence[int]) -> int:
    """Recover omitted f_0 over the integers, not modulo q."""
    tail = tuple(int(value) for value in response_tail)
    if not tail:
        raise ValueError("response tail cannot be empty")
    return -sum((1 << (index + 1)) * value for index, value in enumerate(tail))


def relation_response_is_exactly_zero(response: Sequence[int]) -> bool:
    """Check the cycle relation before any ring reduction."""
    values = tuple(int(value) for value in response)
    if not values:
        return False
    return sum((1 << index) * value for index, value in enumerate(values)) == 0
