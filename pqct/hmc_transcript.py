"""Reduced transcript using the toy HMC commitment component.

This replaces the scalar toy commitment in reduced_transcript.py with the
paper-shaped HMC interface C = G_r*r + G_m*m. It intentionally omits the
partially amortized binary proof, sparse ring challenge, rejection sampler,
and security parameters; it is a reference integration harness only.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from .hmc import HMCError, HMCKey, centered_coefficients
from .ring_commitment import EncodingError, RingElement


class HMCTranscriptError(ValueError):
    """Raised for malformed or unsatisfiable HMC transcript inputs."""


def _frame(*parts: bytes) -> bytes:
    out = bytearray(b"PQCT-HMC-TRANSCRIPT-V1")
    for part in parts:
        out.extend(len(part).to_bytes(4, "big"))
        out.extend(part)
    return bytes(out)


def _encode_vector(values: Sequence[RingElement]) -> bytes:
    return _frame(*(value.encode() for value in values))


def _zero(params) -> RingElement:
    return RingElement.zero(params)


def _add_vectors(left: Sequence[RingElement], right: Sequence[RingElement]) -> tuple[RingElement, ...]:
    if len(left) != len(right):
        raise HMCTranscriptError("vector dimensions differ")
    return tuple(a.add(b) for a, b in zip(left, right))


def _scale_vector(scalar: int, values: Sequence[RingElement]) -> tuple[RingElement, ...]:
    return tuple(value.scalar_mul(scalar) for value in values)


def _sub_vectors(left: Sequence[RingElement], right: Sequence[RingElement]) -> tuple[RingElement, ...]:
    return tuple(a.sub(b) for a, b in zip(left, right))


def _scalar_ring(params, value: int) -> RingElement:
    return RingElement.from_coeffs((value,) + (0,) * (params.n - 1), params)


def derive_hmc_challenge(
    key: HMCKey,
    statement: bytes,
    relation_commitment: Sequence[RingElement],
    mask_commitment: Sequence[RingElement],
) -> int:
    """Derive a nonzero scalar toy challenge from a bound transcript."""
    if not statement:
        raise HMCTranscriptError("statement cannot be empty")
    if len(relation_commitment) != key.ring_rows or len(mask_commitment) != key.ring_rows:
        raise HMCTranscriptError("commitment dimensions differ")
    digest = sha256(
        _frame(b"challenge", key.encode(), statement, _encode_vector(relation_commitment), _encode_vector(mask_commitment))
    ).digest()
    # Toy harness only: Gao's real challenge is a sampled ring element. A
    # scalar challenge spanning all of q would wrap the toy ring and destroy
    # the exact integer relation we are explicitly testing here.
    toy_challenge_bound = min(key.params.q - 1, 31)
    return 1 + (int.from_bytes(digest, "big") % toy_challenge_bound)


def _reconstruct_first(tail: Sequence[RingElement]) -> RingElement:
    if not tail:
        raise HMCTranscriptError("response tail cannot be empty")
    params = tail[0].params
    result = _zero(params)
    for index, value in enumerate(tail, start=1):
        result = result.sub(value.scalar_mul(1 << index))
    return result


def _first_is_integer_representable(first: RingElement, tail: Sequence[RingElement]) -> bool:
    """Reject a first coordinate whose centered integer reconstruction wraps q."""
    params = first.params
    raw = [0] * params.n
    for index, value in enumerate(tail, start=1):
        for component, coefficient in enumerate(centered_coefficients(value)):
            raw[component] -= (1 << index) * coefficient
    half = params.q // 2
    return all(-half <= value <= half for value in raw) and tuple(raw) == tuple(centered_coefficients(first))


def _relation_is_exactly_zero(values: Sequence[RingElement]) -> bool:
    if not values:
        return False
    params = values[0].params
    totals = [0] * params.n
    for index, value in enumerate(values):
        for component, coefficient in enumerate(centered_coefficients(value)):
            totals[component] += (1 << index) * coefficient
    return all(total == 0 for total in totals)


@dataclass(frozen=True)
class HMCProof:
    mask_commitment: tuple[RingElement, ...]
    response_tail: tuple[RingElement, ...]
    opening_response: tuple[RingElement, ...]


def prove_hmc_relation(
    key: HMCKey,
    statement: bytes,
    columns: Sequence[RingElement],
    relation_opening: Sequence[RingElement],
    mask: Sequence[RingElement],
    mask_opening: Sequence[RingElement],
) -> HMCProof:
    """Create the HMC-backed reduced transcript for an exact relation."""
    if len(columns) != key.message_width or len(mask) != key.message_width:
        raise HMCTranscriptError("relation width mismatch")
    if not _relation_is_exactly_zero(columns):
        raise HMCTranscriptError("columns do not satisfy exact ring relation")
    if not _first_is_integer_representable(_reconstruct_first(columns[1:]), columns[1:]):
        raise HMCTranscriptError("relation first coordinate is not representable")
    relation_commitment = key.commit(columns, relation_opening)
    mask_commitment = key.commit(mask, mask_opening)
    challenge = derive_hmc_challenge(key, statement, relation_commitment, mask_commitment)
    response = _add_vectors(_scale_vector(challenge, columns), mask)
    opening_response = _add_vectors(_scale_vector(challenge, relation_opening), mask_opening)
    if not _relation_is_exactly_zero(response):
        raise HMCTranscriptError("masked response relation failed")
    return HMCProof(tuple(mask_commitment), tuple(response[1:]), tuple(opening_response))


def verify_hmc_relation(
    key: HMCKey,
    statement: bytes,
    relation_commitment: Sequence[RingElement],
    proof: HMCProof,
) -> bool:
    """Verify the HMC-backed reduced transcript without binary-proof claims."""
    try:
        if len(proof.response_tail) != key.message_width - 1:
            return False
        if len(proof.opening_response) != key.randomness_width:
            return False
        first = _reconstruct_first(proof.response_tail)
        response = (first, *proof.response_tail)
        if not _first_is_integer_representable(first, proof.response_tail):
            return False
        if not _relation_is_exactly_zero(response):
            return False
        challenge = derive_hmc_challenge(key, statement, relation_commitment, proof.mask_commitment)
        expected = _add_vectors(_scale_vector(challenge, relation_commitment), proof.mask_commitment)
        actual = key.commit(response, proof.opening_response)
        return actual == expected
    except (HMCError, HMCTranscriptError, EncodingError, TypeError, ValueError, OverflowError):
        return False
