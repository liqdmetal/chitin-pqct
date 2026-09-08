"""Reduced linear-relation transcript harness.

This is a deliberately small, non-lattice reference component. It exercises
Gao et al.'s cycle-masked response relation and transcript boundary using a toy
modular linear commitment. It is not a post-quantum proof, not a range proof,
and not suitable for money or consensus.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets
from typing import Protocol, Sequence

from .cycle_masking import derive_cycle_mask, reconstruct_first_response, relation_response_is_exactly_zero


class TranscriptError(ValueError):
    """Raised when a reduced transcript is malformed or invalid."""


class IntSampler(Protocol):
    def sample(self, lower: int, upper: int) -> int:
        """Return an integer uniformly or test-deterministically in bounds."""


class SystemIntSampler:
    """CSPRNG-backed bounded integer sampler for harness experiments."""

    def sample(self, lower: int, upper: int) -> int:
        if lower > upper:
            raise ValueError("invalid sampling interval")
        return lower + secrets.randbelow(upper - lower + 1)


class SequenceIntSampler:
    """Deterministic sampler for test vectors; never use for secrets."""

    def __init__(self, values: Sequence[int]) -> None:
        self._values = tuple(values)
        self._index = 0

    def sample(self, lower: int, upper: int) -> int:
        if self._index >= len(self._values):
            raise AssertionError("deterministic sampler exhausted")
        value = self._values[self._index]
        self._index += 1
        if value < lower or value > upper:
            raise AssertionError("test sample outside requested interval")
        return value


def _encode_uint(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TranscriptError("expected non-negative integer")
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return len(raw).to_bytes(4, "big") + raw


def _encode_sint(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TranscriptError("expected integer")
    sign = b"-" if value < 0 else b"+"
    magnitude = abs(value)
    return sign + _encode_uint(magnitude)


def _frame(*parts: bytes) -> bytes:
    out = bytearray(b"PQCT-REDUCED-TRANSCRIPT-V1")
    for part in parts:
        out.extend(len(part).to_bytes(4, "big"))
        out.extend(part)
    return bytes(out)


@dataclass(frozen=True)
class ToyVectorCommitmentKey:
    """Toy scalar commitment key; no lattice security claim."""

    generators: tuple[int, ...]
    randomness_generator: int
    modulus: int

    def __post_init__(self) -> None:
        if len(self.generators) < 2:
            raise ValueError("at least two message generators are required")
        if self.modulus <= 2:
            raise ValueError("modulus must be greater than two")
        if self.randomness_generator % self.modulus == 0:
            raise ValueError("randomness generator must be nonzero")
        if any(generator % self.modulus == 0 for generator in self.generators):
            raise ValueError("message generators must be nonzero")

    @property
    def width(self) -> int:
        return len(self.generators)

    def encode(self) -> bytes:
        return _frame(
            b"toy-vector-commitment-key",
            _encode_uint(self.modulus),
            _encode_uint(len(self.generators)),
            *(_encode_uint(generator % self.modulus) for generator in self.generators),
            _encode_uint(self.randomness_generator % self.modulus),
        )

    def commit(self, message: Sequence[int], randomness: int) -> int:
        if len(message) != self.width:
            raise TranscriptError("message width mismatch")
        if not isinstance(randomness, int) or isinstance(randomness, bool):
            raise TranscriptError("randomness must be an integer")
        value = sum(generator * coordinate for generator, coordinate in zip(self.generators, message))
        value += self.randomness_generator * randomness
        return value % self.modulus


@dataclass(frozen=True)
class ReducedProof:
    """Proof response with the first packed coordinate omitted."""

    mask_commitment: int
    response_tail: tuple[int, ...]
    opening_response: int


def derive_challenge(
    key: ToyVectorCommitmentKey,
    statement: bytes,
    relation_commitment: int,
    mask_commitment: int,
) -> int:
    """Derive an unbiased nonzero challenge in [1, q-1]."""
    if not statement:
        raise TranscriptError("statement context cannot be empty")
    if not 0 <= relation_commitment < key.modulus:
        raise TranscriptError("noncanonical relation commitment")
    if not 0 <= mask_commitment < key.modulus:
        raise TranscriptError("noncanonical mask commitment")
    span = key.modulus - 1
    limit = (1 << 256) - ((1 << 256) % span)
    counter = 0
    while True:
        digest = hashlib.sha256(
            _frame(
                b"challenge",
                key.encode(),
                statement,
                _encode_uint(relation_commitment),
                _encode_uint(mask_commitment),
                _encode_uint(counter),
            )
        ).digest()
        candidate = int.from_bytes(digest, "big")
        if candidate < limit:
            return 1 + (candidate % span)
        counter += 1


@dataclass(frozen=True)
class ReducedRelationParameters:
    mask_sample_bound: int
    response_bound: int
    opening_bound: int

    def __post_init__(self) -> None:
        if min(self.mask_sample_bound, self.response_bound, self.opening_bound) < 0:
            raise ValueError("bounds must be nonnegative")


def prove_reduced_relation(
    key: ToyVectorCommitmentKey,
    statement: bytes,
    columns: Sequence[int],
    relation_opening: int,
    sampler: IntSampler,
    params: ReducedRelationParameters,
) -> ReducedProof:
    """Create a reduced cycle-masked transcript for a known exact relation.

    The caller must supply a relation opening. A real construction would obtain
    this opening through a linear combination of bit-commitment openings and
    would add the missing binary proof; this harness deliberately does not.
    """
    c = tuple(int(value) for value in columns)
    if len(c) != key.width:
        raise TranscriptError("relation width mismatch")
    if not relation_response_is_exactly_zero(c):
        raise TranscriptError("columns do not satisfy the exact weighted relation")
    if not isinstance(relation_opening, int) or isinstance(relation_opening, bool):
        raise TranscriptError("relation opening must be an integer")
    relation_commitment = key.commit(c, relation_opening)

    sampled = (0,) + tuple(
        sampler.sample(-params.mask_sample_bound, params.mask_sample_bound)
        for _ in range(key.width - 1)
    ) + (0,)
    mask = derive_cycle_mask(sampled)
    mask_opening = sampler.sample(-params.opening_bound, params.opening_bound)
    mask_commitment = key.commit(mask.values, mask_opening)
    challenge = derive_challenge(key, statement, relation_commitment, mask_commitment)
    response = tuple(challenge * value + mask_value for value, mask_value in zip(c, mask.values))
    opening_response = challenge * relation_opening + mask_opening

    if max(abs(value) for value in response) > params.response_bound:
        raise TranscriptError("response exceeds configured norm bound")
    if abs(opening_response) > params.opening_bound:
        raise TranscriptError("opening response exceeds configured bound")
    if not relation_response_is_exactly_zero(response):
        raise TranscriptError("cycle-masked response relation failed")
    return ReducedProof(mask_commitment, tuple(response[1:]), opening_response)


def verify_reduced_relation(
    key: ToyVectorCommitmentKey,
    statement: bytes,
    relation_commitment: int,
    proof: ReducedProof,
    params: ReducedRelationParameters,
) -> bool:
    """Verify the reduced transcript with exact integer and modular checks."""
    try:
        if len(proof.response_tail) != key.width - 1:
            return False
        if not 0 <= relation_commitment < key.modulus:
            return False
        if not 0 <= proof.mask_commitment < key.modulus:
            return False
        if max(abs(value) for value in proof.response_tail) > params.response_bound:
            return False
        if abs(proof.opening_response) > params.opening_bound:
            return False
        first = reconstruct_first_response(proof.response_tail)
        response = (first, *proof.response_tail)
        if max(abs(value) for value in response) > params.response_bound:
            return False
        if not relation_response_is_exactly_zero(response):
            return False
        challenge = derive_challenge(key, statement, relation_commitment, proof.mask_commitment)
        expected = (challenge * relation_commitment + proof.mask_commitment) % key.modulus
        actual = key.commit(response, proof.opening_response)
        return actual == expected
    except (TranscriptError, TypeError, ValueError, OverflowError):
        return False
