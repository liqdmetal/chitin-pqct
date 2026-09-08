"""Arithmetic boundary for the partially amortized binary proof.

This file implements the exact bit/mask identities and the batched linear
opening equation from Gao et al.'s Protocol 1 using the lab's toy scalar
commitment. It is not the complete lattice proof: no lattice commitment,
Gaussian sampler, rejection transcript, or security reduction is provided.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .reduced_transcript import ToyVectorCommitmentKey, TranscriptError


@dataclass(frozen=True)
class BinaryIdentity:
    bits: tuple[int, ...]
    mask: tuple[int, ...]
    challenge: int
    response: tuple[int, ...]
    quadratic_mask: tuple[int, ...]
    linear_mask: tuple[int, ...]

    def __post_init__(self) -> None:
        widths = {len(self.bits), len(self.mask), len(self.response), len(self.quadratic_mask), len(self.linear_mask)}
        if len(widths) != 1 or not self.bits:
            raise ValueError("binary identity vectors must have equal nonzero width")
        if any(bit not in (0, 1) for bit in self.bits):
            raise ValueError("bits must be binary")


def _checked_vector(values: Sequence[int]) -> tuple[int, ...]:
    result = tuple(values)
    if not result:
        raise ValueError("vector cannot be empty")
    if any(not isinstance(value, int) or isinstance(value, bool) for value in result):
        raise TypeError("vector coordinates must be integers")
    return result


def build_binary_identity(bits: Sequence[int], mask: Sequence[int], challenge: int) -> BinaryIdentity:
    """Build g=x*b+t and the two commitments' message vectors."""
    b = _checked_vector(bits)
    t = _checked_vector(mask)
    if len(b) != len(t):
        raise ValueError("bits and mask dimensions differ")
    if any(bit not in (0, 1) for bit in b):
        raise ValueError("bits must be binary")
    if not isinstance(challenge, int) or isinstance(challenge, bool):
        raise TypeError("challenge must be an integer")
    response = tuple(challenge * bit + value for bit, value in zip(b, t))
    quadratic_mask = tuple(value * (1 - 2 * bit) for bit, value in zip(b, t))
    linear_mask = tuple(-value * value for value in t)
    return BinaryIdentity(b, t, challenge, response, quadratic_mask, linear_mask)


def verify_binary_identity(identity: BinaryIdentity) -> bool:
    """Check g*(x-g) = x*t*(1-2b) - t² coordinate-wise."""
    return all(
        g * (identity.challenge - g) == identity.challenge * e + f
        for g, e, f in zip(identity.response, identity.quadratic_mask, identity.linear_mask)
    )


def batch_linear_opening(
    key: ToyVectorCommitmentKey,
    bit_commitments: Sequence[int],
    bits: Sequence[Sequence[int]],
    masks: Sequence[Sequence[int]],
    bit_openings: Sequence[int],
    mask_openings: Sequence[int],
    weights: Sequence[int],
    challenge: int,
) -> bool:
    """Check the partial-amortization opening equation exactly modulo q.

    Public commitments are supplied separately from private openings. That
    separation is essential: recomputing commitments from the supplied opening
    would make a tampered opening self-consistent and would not test binding.
    """
    count = len(bits)
    if not (count and len(bit_commitments) == len(masks) == len(bit_openings) == len(mask_openings) == len(weights) == count):
        raise ValueError("batched input dimensions differ")
    if any(not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < key.modulus for value in bit_commitments):
        raise ValueError("bit commitments must be canonical scalars")
    if any(len(vector) != key.width for vector in (*bits, *masks)):
        raise ValueError("batched vector width differs from commitment key")
    if not isinstance(challenge, int) or isinstance(challenge, bool):
        raise TypeError("challenge must be an integer")
    identities = [build_binary_identity(b, t, challenge) for b, t in zip(bits, masks)]
    aggregate_bits = tuple(sum(weight * identity.response[j] for weight, identity in zip(weights, identities)) for j in range(key.width))
    aggregate_mask = tuple(sum(weight * identity.mask[j] for weight, identity in zip(weights, identities)) for j in range(key.width))
    aggregate_opening = sum(weight * (challenge * rb + rt) for weight, rb, rt in zip(weights, bit_openings, mask_openings))
    batched_mask_commitment = key.commit(aggregate_mask, sum(weight * rt for weight, rt in zip(weights, mask_openings)))
    left = (challenge * sum(weight * commitment for weight, commitment in zip(weights, bit_commitments)) + batched_mask_commitment) % key.modulus
    right = key.commit(aggregate_bits, aggregate_opening)
    return left == right and all(verify_binary_identity(identity) for identity in identities)
