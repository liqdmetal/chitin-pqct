"""Sparse ring challenge sampler for research experiments.

This implements the paper's challenge-set shape C_{w,p}: exactly `w`
nonzero coefficients, each equal to +/-p, with degree exactly n-1.
It is not a security claim and is not the full Fiat-Shamir instantiation.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import shake_256

from .ring_commitment import RingElement, ToyParameters


class ChallengeError(ValueError):
    pass


@dataclass(frozen=True)
class SparseChallenge:
    element: RingElement
    positions: tuple[int, ...]
    coefficients: tuple[int, ...]

    def __post_init__(self) -> None:
        if len(self.positions) != len(self.coefficients):
            raise ChallengeError("challenge metadata dimensions differ")
        if len(set(self.positions)) != len(self.positions):
            raise ChallengeError("challenge positions must be unique")
        if tuple(sorted(self.positions)) != self.positions:
            raise ChallengeError("challenge positions must be sorted")
        if any(position < 0 or position >= self.element.params.n for position in self.positions):
            raise ChallengeError("challenge position outside ring")
        if any(coefficient == 0 for coefficient in self.coefficients):
            raise ChallengeError("challenge coefficients must be nonzero")
        expected = [0] * self.element.params.n
        for position, coefficient in zip(self.positions, self.coefficients):
            expected[position] = coefficient
        if self.element != RingElement.from_coeffs(expected, self.element.params):
            raise ChallengeError("challenge metadata does not match element")

    @property
    def hamming_weight(self) -> int:
        return len(self.positions)

    @property
    def weight(self) -> int:
        """Compatibility alias for the paper's HW(x) notation."""
        return self.hamming_weight

    def as_ring_element(self) -> RingElement:
        return self.element


def _bounded_uniform(seed: bytes, label: bytes, count: int, bound: int) -> list[int]:
    if not seed or count < 0 or bound <= 0:
        raise ChallengeError("invalid challenge sampler input")
    width = (bound.bit_length() + 7) // 8
    limit = (1 << (8 * width)) - ((1 << (8 * width)) % bound)
    result: list[int] = []
    counter = 0
    while len(result) < count:
        block = shake_256(seed + label + counter.to_bytes(8, "big")).digest(width * 64)
        counter += 1
        for offset in range(0, len(block) - width + 1, width):
            value = int.from_bytes(block[offset : offset + width], "big")
            if value < limit:
                result.append(value % bound)
                if len(result) == count:
                    break
    return result


def sample_sparse_challenge(
    seed: bytes,
    params: ToyParameters,
    weight: int,
    coefficient_bound: int,
) -> SparseChallenge:
    """Sample the paper-shaped ``C_{w,p}`` experiment set.

    Gao et al. define C by deg(x)=n-1, HW(x)=w, and ||x||_inf=p.
    The highest coefficient is therefore nonzero and every nonzero
    coefficient has magnitude exactly p. This sampler is deterministic and
    intended for vectors and tests, not as a claimed secure Fiat-Shamir map.
    """
    if weight <= 0 or weight > params.n:
        raise ChallengeError("challenge weight outside ring dimension")
    if coefficient_bound <= 0 or 2 * coefficient_bound >= params.q:
        raise ChallengeError("challenge coefficient bound invalid for modulus")
    if weight == 1:
        positions = (params.n - 1,)
    else:
        lower = tuple(sorted(_bounded_uniform(seed, b"positions", weight - 1, params.n - 1)))
        counter = 1
        while len(set(lower)) != weight - 1:
            lower = tuple(sorted(_bounded_uniform(seed, b"positions" + counter.to_bytes(4, "big"), weight - 1, params.n - 1)))
            counter += 1
        positions = (*lower, params.n - 1)
    signs = _bounded_uniform(seed, b"signs", weight, 2)
    coefficients = tuple(coefficient_bound * (1 if sign else -1) for sign in signs)
    values = [0] * params.n
    for position, coefficient in zip(positions, coefficients):
        values[position] = coefficient
    return SparseChallenge(RingElement.from_coeffs(values, params), positions, coefficients)
