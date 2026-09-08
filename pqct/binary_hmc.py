"""Research-only Protocol-1-shaped binary transcript scaffold.

This module intentionally does *not* claim to implement Gao et al.'s complete
proof. It preserves the algebraic E/F/G transcript shape while enforcing the
public bit-commitment relation at the API boundary. Exact D1/D2/SB sampling,
rejection sampling, ring-valued Fiat-Shamir, and the security reduction remain
separate unfinished work.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from .hmc import HMCError, HMCKey, infinity_norm
from .ring_commitment import EncodingError, RingElement


class BinaryTranscriptError(ValueError):
    """Raised for malformed or unsatisfiable binary-proof inputs."""


def _scalar_ring(params, value: int) -> RingElement:
    return RingElement.from_coeffs((value,) + (0,) * (params.n - 1), params)


def _frame(*parts: bytes) -> bytes:
    result = bytearray(b"PQCT-BINARY-HMC-V1")
    for part in parts:
        result.extend(len(part).to_bytes(4, "big"))
        result.extend(part)
    return bytes(result)


def _encode_vector(values: Sequence[RingElement]) -> bytes:
    return _frame(*(value.encode() for value in values))


def _encode_commitments(values: Sequence[Sequence[RingElement]]) -> bytes:
    return _frame(*(_encode_vector(row) for row in values))


def _zero(params) -> RingElement:
    return RingElement.zero(params)


def _add(left: Sequence[RingElement], right: Sequence[RingElement]) -> tuple[RingElement, ...]:
    if len(left) != len(right):
        raise BinaryTranscriptError("vector dimensions differ")
    return tuple(a.add(b) for a, b in zip(left, right))


def _scale(scalar: int, values: Sequence[RingElement]) -> tuple[RingElement, ...]:
    return tuple(value.scalar_mul(scalar) for value in values)


def _flatten(vectors: Sequence[Sequence[RingElement]]) -> tuple[RingElement, ...]:
    return tuple(element for vector in vectors for element in vector)


def _check_vector(values: Sequence[RingElement], key: HMCKey, width: int) -> tuple[RingElement, ...]:
    result = tuple(values)
    if len(result) != width:
        raise BinaryTranscriptError("vector width mismatch")
    if any(value.params != key.params for value in result):
        raise BinaryTranscriptError("ring parameter mismatch")
    return result


def _check_opening(values: Sequence[RingElement], key: HMCKey) -> tuple[RingElement, ...]:
    result = tuple(values)
    if len(result) != key.randomness_width:
        raise BinaryTranscriptError("opening width mismatch")
    if any(value.params != key.params for value in result):
        raise BinaryTranscriptError("opening parameter mismatch")
    return result


@dataclass(frozen=True)
class BinaryProofParameters:
    """Toy norm bounds; not paper security parameters."""

    response_bound: int
    opening_bound: int

    def __post_init__(self) -> None:
        if self.response_bound < 0 or self.opening_bound < 0:
            raise ValueError("bounds must be nonnegative")


@dataclass(frozen=True)
class BinaryProof:
    commitment_e: tuple[RingElement, ...]
    commitment_f: tuple[RingElement, ...]
    commitment_g: tuple[RingElement, ...]
    responses_g: tuple[tuple[RingElement, ...], ...]
    response_zg: tuple[RingElement, ...]
    response_zb: tuple[RingElement, ...]


def derive_binary_challenge(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    commitment_e: Sequence[RingElement],
    commitment_f: Sequence[RingElement],
    commitment_g: Sequence[RingElement],
) -> int:
    """Derive the bounded scalar challenge used only by this toy harness."""
    if not statement:
        raise BinaryTranscriptError("statement cannot be empty")
    transcript = _frame(
        b"challenge", statement, base_key.encode(), key_e.encode(), key_f.encode(), key_g.encode(),
        _encode_commitments(bit_commitments),
        _encode_vector(commitment_e), _encode_vector(commitment_f), _encode_vector(commitment_g),
    )
    return 1 + (int.from_bytes(sha256(transcript).digest(), "big") % min(31, base_key.params.q - 1))


def _check_public_bit_commitments(
    base_key: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    bits: Sequence[Sequence[int]],
    openings: Sequence[Sequence[RingElement]],
) -> None:
    """Enforce B_i = Com_ck(b_i; r_b,i) for every public bit commitment.

    This is a witness-side consistency check in the research harness. A real
    zero-knowledge proof must establish this relation without exposing bits or
    openings; Protocol 1's complete transcript is still not implemented here.
    """
    for public, vector, opening in zip(bit_commitments, bits, openings):
        message = tuple(_scalar_ring(base_key.params, bit) for bit in vector)
        expected = base_key.commit(message, opening)
        if tuple(public) != expected:
            raise BinaryTranscriptError("public bit commitment does not match witness")


def prove_binary(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    bits: Sequence[Sequence[int]],
    bit_openings: Sequence[Sequence[RingElement]],
    masks: Sequence[Sequence[Sequence[RingElement]]],
    mask_opening_e: Sequence[RingElement],
    mask_opening_f: Sequence[RingElement],
    mask_opening_g: Sequence[RingElement],
    params: BinaryProofParameters,
) -> BinaryProof:
    """Create the algebraic scaffold after checking every public opening."""
    try:
        count = len(bits)
        if count == 0 or count > 2:
            raise BinaryTranscriptError("toy Protocol 1 requires one or two bit vectors")
        width = base_key.message_width
        if len(bit_commitments) != count or len(bit_openings) != count or len(masks) != count:
            raise BinaryTranscriptError("binary proof dimensions differ")
        checked_bits = []
        checked_openings = []
        checked_masks = []
        for index in range(count):
            vector = tuple(bits[index])
            if len(vector) != width or any(bit not in (0, 1) for bit in vector):
                raise BinaryTranscriptError("bits must be binary and match key width")
            checked_bits.append(vector)
            checked_openings.append(_check_opening(bit_openings[index], base_key))
            if len(masks[index]) != width:
                raise BinaryTranscriptError("mask column count differs")
            checked_masks.append(tuple(_check_vector(column, base_key, 1) for column in masks[index]))
            if len(bit_commitments[index]) != base_key.ring_rows:
                raise BinaryTranscriptError("public commitment row count differs")
        _check_public_bit_commitments(base_key, bit_commitments, checked_bits, checked_openings)
        t = tuple(tuple(column[0] for column in columns) for columns in checked_masks)
        if key_e != key_f:
            raise BinaryTranscriptError("toy scaffold requires compatible E/F commitment keys")
        if key_g != base_key:
            raise BinaryTranscriptError("toy scaffold requires G and B commitments to share a key")
        if key_e.message_width != count * width or key_g.message_width != width:
            raise BinaryTranscriptError("E/F/G HMC message widths do not match")
        if len(mask_opening_e) != key_e.randomness_width or len(mask_opening_f) != key_f.randomness_width or len(mask_opening_g) != key_g.randomness_width:
            raise BinaryTranscriptError("mask opening dimensions differ")
        e_message = _flatten(tuple(tuple(t[i][j].scalar_mul(1 - 2 * checked_bits[i][j]) for j in range(width)) for i in range(count)))
        f_message = _flatten(tuple(tuple(t[i][j].mul(t[i][j]).scalar_mul(-1) for j in range(width)) for i in range(count)))
        g_message = tuple(t[1][j] if count == 2 else t[0][j].scalar_mul(0) for j in range(width))
        commitment_e = key_e.commit(e_message, mask_opening_e)
        commitment_f = key_f.commit(f_message, mask_opening_f)
        commitment_g = key_g.commit(g_message, mask_opening_g)
        challenge = derive_binary_challenge(statement, base_key, key_e, key_f, key_g, bit_commitments, commitment_e, commitment_f, commitment_g)
        responses = tuple(tuple(t[i][j].add(_scalar_ring(t[i][j].params, challenge * checked_bits[i][j])) for j in range(width)) for i in range(count))
        response_zg = _add(_scale(challenge, mask_opening_e), mask_opening_f)
        weighted_opening = checked_openings[1] if count == 2 else tuple(_zero(base_key.params) for _ in range(key_g.randomness_width))
        response_zb = _add(_scale(challenge, weighted_opening), mask_opening_g)
        if infinity_norm((*_flatten(responses), *response_zg, *response_zb)) > params.response_bound:
            raise BinaryTranscriptError("binary response exceeds configured bound")
        if infinity_norm((*mask_opening_e, *mask_opening_f, *mask_opening_g)) > params.opening_bound:
            raise BinaryTranscriptError("binary opening exceeds configured bound")
        return BinaryProof(commitment_e, commitment_f, commitment_g, responses, response_zg, response_zb)
    except (HMCError, EncodingError, TypeError, ValueError) as error:
        if isinstance(error, BinaryTranscriptError):
            raise
        raise BinaryTranscriptError(str(error)) from error


def verify_binary(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    proof: BinaryProof,
    params: BinaryProofParameters,
) -> bool:
    """Verify the algebraic scaffold; no soundness/security claim."""
    try:
        count = len(bit_commitments)
        width = base_key.message_width
        if count == 0 or count > 2 or len(proof.responses_g) != count:
            return False
        if any(len(response) != width for response in proof.responses_g):
            return False
        if infinity_norm((*_flatten(proof.responses_g), *proof.response_zg, *proof.response_zb)) > params.response_bound:
            return False
        challenge = derive_binary_challenge(statement, base_key, key_e, key_f, key_g, bit_commitments, proof.commitment_e, proof.commitment_f, proof.commitment_g)
        quadratic_message = _flatten(tuple(tuple(response.scalar_mul(challenge).sub(response.mul(response)) for response in vector) for vector in proof.responses_g))
        expected_e = key_e.commit(quadratic_message, proof.response_zg)
        lhs_e = _add(_scale(challenge, proof.commitment_e), proof.commitment_f)
        if lhs_e != expected_e:
            return False
        aggregate_g = tuple(proof.responses_g[1][j] if count == 2 else proof.responses_g[0][j].scalar_mul(0) for j in range(width))
        if len(proof.response_zb) != key_g.randomness_width:
            return False
        aggregate_b = tuple(_zero(base_key.params) for _ in range(base_key.ring_rows))
        for index, commitment in enumerate(bit_commitments):
            aggregate_b = _add(aggregate_b, _scale(index, commitment))
        lhs_g = _add(_scale(challenge, aggregate_b), proof.commitment_g)
        expected_g = key_g.commit(aggregate_g, proof.response_zb)
        return lhs_g == expected_g
    except (HMCError, BinaryTranscriptError, EncodingError, TypeError, ValueError, OverflowError):
        return False
