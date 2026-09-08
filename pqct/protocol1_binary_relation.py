"""Binary-relation extraction (Gao Appendix B equations 38-45)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .binary_protocol1_ring import RingProtocol1Proof
from .hmc import centered_coefficients
from .ring_commitment import RingElement


class BinaryRelationError(ValueError):
    """Malformed extraction input."""


@dataclass(frozen=True)
class BinaryWitnessCheck:
    """A relaxed bit derived from two accepting transcripts' g values.

    This is a raw divided-difference output ONLY. It is not itself a
    proof that the underlying witness is binary -- see the module
    docstring for exactly what remains unimplemented.
    """

    row: int
    column: int
    relaxed_bit: tuple[int, ...]


def _centered(value: RingElement) -> tuple[int, ...]:
    return centered_coefficients(value)


def extract_binary_witness_row(
    proofs: Sequence[RingProtocol1Proof],
    challenges: Sequence[RingElement],
    row: int,
    column: int,
) -> BinaryWitnessCheck:
    """Derive a relaxed b_{i,j} from two accepting x transcripts.

    g_{i,j}(x) = x*b_{i,j} + t_{i,j} is per-(i,j) in the public transcript
    (unlike z_b, it is never zeta-aggregated -- see paper text lines
    2163-2211), so the divided difference

        y*b_{i,j} = g_{i,j}(x0) - g_{i,j}(x1),  y = x0 - x1

    needs no unbatching step. This mirrors the paper's equation
    (34)-style relaxed opening, specialized to a scalar bit.
    """
    if len(proofs) < 2 or len(challenges) < 2:
        raise BinaryRelationError("at least two transcripts are required")
    if len(proofs) != len(challenges):
        raise BinaryRelationError("proof/challenge count mismatch")
    params = challenges[0].params
    if any(c.params != params for c in challenges):
        raise BinaryRelationError("challenge parameter mismatch")
    g0 = proofs[0].responses_g[row][column]
    g1 = proofs[1].responses_g[row][column]
    if g0.params != params or g1.params != params:
        raise BinaryRelationError("response parameter mismatch")
    left, right = _centered(g0), _centered(g1)
    if len(left) != len(right):
        raise BinaryRelationError("polynomial widths differ")
    relaxed_bit = tuple(a - b for a, b in zip(left, right))
    return BinaryWitnessCheck(row=row, column=column, relaxed_bit=relaxed_bit)


__all__ = ["BinaryRelationError", "BinaryWitnessCheck", "extract_binary_witness_row"]

