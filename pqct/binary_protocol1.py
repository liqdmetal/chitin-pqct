"""Literal Protocol-1-shaped binary proof reference for S <= 2.

This module is a research oracle. It implements the equations from Gao et al.
Protocol 1 with separate per-index z_b responses and a verifier that consumes
only public commitments plus proof responses. It deliberately leaves the
paper's exact D1/D2 distributions and rejection sampler behind explicit
interfaces.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from .hmc import HMCError, HMCKey, centered_coefficients, infinity_norm
from .ring_commitment import EncodingError, RingElement


class Protocol1Error(ValueError):
    """Malformed or unsatisfiable Protocol 1 reference input."""


def _frame(*parts: bytes) -> bytes:
    out = bytearray(b"PQCT-PBIN-V1")
    for part in parts:
        out.extend(len(part).to_bytes(4, "big"))
        out.extend(part)
    return bytes(out)


def _encode_vec(values: Sequence[RingElement]) -> bytes:
    return _frame(*(value.encode() for value in values))


def _encode_rows(values: Sequence[Sequence[RingElement]]) -> bytes:
    return _frame(*(_encode_vec(row) for row in values))


def _zero(params) -> RingElement:
    return RingElement.zero(params)


def _sum_elements(elements, params) -> RingElement:
    result = _zero(params)
    for element in elements:
        result = result.add(element)
    return result


def _add(left: Sequence[RingElement], right: Sequence[RingElement]) -> tuple[RingElement, ...]:
    if len(left) != len(right):
        raise Protocol1Error("vector dimensions differ")
    return tuple(a.add(b) for a, b in zip(left, right))


def _sub(left: Sequence[RingElement], right: Sequence[RingElement]) -> tuple[RingElement, ...]:
    if len(left) != len(right):
        raise Protocol1Error("vector dimensions differ")
    return tuple(a.sub(b) for a, b in zip(left, right))


def _scale(scalar: int, values: Sequence[RingElement]) -> tuple[RingElement, ...]:
    return tuple(value.scalar_mul(scalar) for value in values)


def _flatten(rows: Sequence[Sequence[RingElement]]) -> tuple[RingElement, ...]:
    return tuple(element for row in rows for element in row)


def _scalar(params, value: int) -> RingElement:
    return RingElement.from_coeffs((value,) + (0,) * (params.n - 1), params)


def _canonical_rows(rows: Sequence[Sequence[RingElement]], count: int, width: int, params) -> tuple[tuple[RingElement, ...], ...]:
    result = tuple(tuple(row) for row in rows)
    if len(result) != count or any(len(row) != width for row in result):
        raise Protocol1Error("row dimensions differ")
    if any(value.params != params for row in result for value in row):
        raise Protocol1Error("row parameter mismatch")
    return result


def derive_protocol1_challenge(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    commitment_e: Sequence[RingElement],
    commitment_f: Sequence[RingElement],
    commitment_g: Sequence[RingElement],
    challenge_bound: int,
) -> int:
    """Derive a bounded scalar only for this reference oracle.

    The paper's challenge is ring-valued and sparse. This scalar path is kept
    separate and labeled so it cannot be mistaken for the final transform.
    """
    if not statement or challenge_bound <= 0:
        raise Protocol1Error("invalid challenge inputs")
    transcript = _frame(
        b"challenge-scalar-reference",
        statement,
        base_key.encode(), key_e.encode(), key_f.encode(), key_g.encode(),
        _encode_rows(bit_commitments),
        _encode_vec(commitment_e), _encode_vec(commitment_f), _encode_vec(commitment_g),
    )
    return 1 + int.from_bytes(sha256(transcript).digest(), "big") % challenge_bound


@dataclass(frozen=True)
class Protocol1Parameters:
    response_bound: int
    opening_bound: int
    challenge_bound: int
    max_vectors: int = 2

    def __post_init__(self) -> None:
        if min(self.response_bound, self.opening_bound, self.challenge_bound) <= 0:
            raise Protocol1Error("Protocol 1 bounds must be positive")
        if not 1 <= self.max_vectors <= 2:
            raise Protocol1Error("reference implementation supports S <= 2")


@dataclass(frozen=True)
class Protocol1Proof:
    commitment_e: tuple[RingElement, ...]
    commitment_f: tuple[RingElement, ...]
    commitment_g: tuple[RingElement, ...]
    responses_g: tuple[tuple[RingElement, ...], ...]
    response_zg: tuple[RingElement, ...]
    response_zb: tuple[tuple[RingElement, ...], ...]


def _check_binary_commitments(
    key: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    bits: Sequence[Sequence[RingElement]],
    openings: Sequence[Sequence[RingElement]],
) -> None:
    if len(bit_commitments) != len(bits) or len(bits) != len(openings):
        raise Protocol1Error("binary commitment dimensions differ")
    for public, message, opening in zip(bit_commitments, bits, openings):
        if not message:
            raise Protocol1Error("empty bit vector")
        if tuple(public) != key.commit(message, opening):
            raise Protocol1Error("public bit commitment does not match witness")
        for element in message:
            coefficients = centered_coefficients(element)
            if any(value not in (0, 1) for value in coefficients):
                raise Protocol1Error("reference bit encoding must be scalar 0/1")
            if any(value != 0 for value in coefficients[1:]):
                raise Protocol1Error("reference bit encoding must be constant polynomials")


def prove_protocol1(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    bits: Sequence[Sequence[RingElement]],
    openings: Sequence[Sequence[RingElement]],
    masks: Sequence[Sequence[Sequence[RingElement]]],
    mask_opening_e: Sequence[RingElement],
    mask_opening_f: Sequence[RingElement],
    mask_opening_g: Sequence[RingElement],
    params: Protocol1Parameters,
) -> Protocol1Proof:
    """Create a literal per-index Protocol 1 algebra transcript.

    The caller supplies masks and openings so every equation is deterministic.
    No rejection sampling is silently skipped: this reference function applies
    only explicit norm bounds and is not a complete zero-knowledge proof.
    """
    count = len(bits)
    if count == 0 or count > params.max_vectors:
        raise Protocol1Error("unsupported vector count")
    width = len(bits[0])
    if width == 0 or any(len(vector) != width for vector in bits):
        raise Protocol1Error("bit widths differ")
    if len(masks) != count or any(len(row) != width for row in masks):
        raise Protocol1Error("mask dimensions differ")
    _check_binary_commitments(base_key, bit_commitments, bits, openings)
    if key_e.message_width != count * width:
        raise Protocol1Error("E message width must match flattened t_i(1-2b_i)")
    if key_f.message_width != key_e.message_width:
        raise Protocol1Error("F message width must match E")
    if key_g.message_width != width:
        raise Protocol1Error("G message width must match weighted t_i")
    params_ring = base_key.params
    t = tuple(tuple(tuple(row) for row in vector) for vector in masks)
    e_message = tuple(
        t[i][j][0].scalar_mul(1 - 2 * centered_coefficients(bits[i][j])[0])
        for i in range(count) for j in range(width)
    )
    f_message = tuple(
        t[i][j][0].mul(t[i][j][0]).scalar_mul(-1)
        for i in range(count) for j in range(width)
    )
    g_message = tuple(
        _sum_elements((t[i][j][0].scalar_mul(i) for i in range(count)), params_ring)
        for j in range(width)
    )
    commitment_e = key_e.commit(e_message, mask_opening_e)
    commitment_f = key_f.commit(f_message, mask_opening_f)
    commitment_g = key_g.commit(g_message, mask_opening_g)
    challenge = derive_protocol1_challenge(
        statement, base_key, key_e, key_f, key_g, bit_commitments,
        commitment_e, commitment_f, commitment_g, params.challenge_bound,
    )
    responses_g = tuple(
        tuple(t[i][j][0].add(_scalar(params_ring, challenge * centered_coefficients(bits[i][j])[0])) for j in range(width))
        for i in range(count)
    )
    response_zg = _add(_scale(challenge, mask_opening_e), mask_opening_f)
    response_zb = tuple(
        _add(_scale(challenge, openings[i]), tuple(t[i][j][0] for j in range(width)))
        for i in range(count)
    )
    all_responses = _flatten(responses_g) + response_zg + _flatten(response_zb)
    if infinity_norm(all_responses) > params.response_bound:
        raise Protocol1Error("response norm exceeds bound")
    if infinity_norm((*mask_opening_e, *mask_opening_f, *mask_opening_g)) > params.opening_bound:
        raise Protocol1Error("opening norm exceeds bound")
    return Protocol1Proof(commitment_e, commitment_f, commitment_g, responses_g, response_zg, response_zb)


def verify_protocol1(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    proof: Protocol1Proof,
    params: Protocol1Parameters,
) -> bool:
    """Verify only public Protocol 1 equations and explicit norm bounds."""
    try:
        count = len(bit_commitments)
        if count == 0 or count > params.max_vectors:
            return False
        width = len(proof.responses_g[0])
        if width == 0 or len(proof.responses_g) != count:
            return False
        if any(len(row) != width for row in proof.responses_g):
            return False
        if len(proof.response_zb) != count or any(len(row) != width for row in proof.response_zb):
            return False
        if infinity_norm((*_flatten(proof.responses_g), *proof.response_zg, *_flatten(proof.response_zb))) > params.response_bound:
            return False
        challenge = derive_protocol1_challenge(
            statement, base_key, key_e, key_f, key_g, bit_commitments,
            proof.commitment_e, proof.commitment_f, proof.commitment_g, params.challenge_bound,
        )
        g_message = tuple(
            _sum_elements((proof.responses_g[i][j].scalar_mul(i) for i in range(count)), base_key.params)
            for j in range(width)
        )
        weighted_commitment = tuple(
            sum((bit_commitments[i][row].scalar_mul(i) for i in range(count)), _zero(base_key.params))
            for row in range(base_key.ring_rows)
        )
        rhs_g = key_g.commit(g_message, proof.response_zb[-1])
        lhs_g = _add(_scale(challenge, weighted_commitment), proof.commitment_g)
        if lhs_g != rhs_g:
            return False
        e_message = tuple(
            proof.responses_g[i][j].mul(_scalar(base_key.params, challenge).sub(proof.responses_g[i][j]))
            for i in range(count) for j in range(width)
        )
        lhs_e = _add(_scale(challenge, proof.commitment_e), proof.commitment_f)
        rhs_e = key_e.commit(e_message, proof.response_zg)
        return lhs_e == rhs_e
    except (HMCError, Protocol1Error, EncodingError, TypeError, ValueError, OverflowError):
        return False
