"""Sparse ring-valued Fiat-Shamir challenge reference.

This is a transcript-to-challenge codec for the published challenge shape
C_{w,p}. It is not a proof of the security of Fiat-Shamir in the quantum
random-oracle model and is not production cryptography.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import shake_256
from typing import Sequence

from .challenge import ChallengeError, SparseChallenge, sample_sparse_challenge
from .ring_commitment import RingElement, ToyParameters


class RingChallengeError(ValueError):
    """Invalid ring-challenge transcript or parameters."""


@dataclass(frozen=True)
class RingChallengeParameters:
    weight: int
    coefficient_bound: int
    domain: bytes = b"PQCT-FS-RING-CHALLENGE-V1"

    def __post_init__(self) -> None:
        if self.weight <= 0 or self.coefficient_bound <= 0:
            raise RingChallengeError("weight and coefficient bound must be positive")
        if not self.domain or len(self.domain) > 255:
            raise RingChallengeError("domain must contain 1..255 bytes")


def _frame(*parts: bytes) -> bytes:
    output = bytearray(b"PQCT-RING-FS-V1")
    for part in parts:
        output.extend(len(part).to_bytes(8, "big"))
        output.extend(part)
    return bytes(output)


def _hash_seed(
    statement: bytes,
    params: ToyParameters,
    challenge_params: RingChallengeParameters,
    commitments: Sequence[Sequence[RingElement]],
) -> bytes:
    if not statement:
        raise RingChallengeError("statement cannot be empty")
    if any(element.params != params for row in commitments for element in row):
        raise RingChallengeError("commitment parameter mismatch")
    encoded = _frame(
        challenge_params.domain,
        statement,
        params.n.to_bytes(4, "big"),
        params.q.to_bytes(8, "big"),
        params.k.to_bytes(4, "big"),
        *(_frame(*(element.encode() for element in row)) for row in commitments),
    )
    return shake_256(encoded).digest(32)


def derive_ring_challenge(
    statement: bytes,
    params: ToyParameters,
    challenge_params: RingChallengeParameters,
    commitments: Sequence[Sequence[RingElement]],
) -> SparseChallenge:
    """Derive a deterministic sparse ring challenge from a full transcript."""
    seed = _hash_seed(statement, params, challenge_params, commitments)
    try:
        return sample_sparse_challenge(
            seed + shake_256(seed + b"/retry").digest(32),
            params,
            challenge_params.weight,
            challenge_params.coefficient_bound,
        )
    except ChallengeError as error:
        raise RingChallengeError(str(error)) from error


def challenge_ring_element(challenge: SparseChallenge) -> RingElement:
    """Convert challenge metadata to the canonical ring element."""
    return challenge.as_ring_element()
