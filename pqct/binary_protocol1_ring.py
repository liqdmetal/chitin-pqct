"""Ring-valued Protocol 1 equation reference.

This module mirrors the public algebra of Gao et al. IACR 2021/1674,
Protocol 1, using the paper's two public challenges:

* zeta is derived before E/F/G and supplies the zeta**i aggregation;
* x is derived after E/F/G and masks the bit witnesses.

It is still research code. The high-level sampled prover is separate because
finite-support distributions and rejection decisions are not a security proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Sequence

from .hmc import HMCError, HMCKey, centered_coefficients, infinity_norm
from .ring_challenge import RingChallengeParameters, derive_ring_challenge
from .ring_commitment import EncodingError, RingElement


class RingProtocol1Error(ValueError):
    """Malformed or dimensionally invalid ring Protocol 1 input."""


def _zero(params) -> RingElement:
    return RingElement.zero(params)


def _sum_elements(elements: Sequence[RingElement], params) -> RingElement:
    result = _zero(params)
    for element in elements:
        result = result.add(element)
    return result


def _add(left: Sequence[RingElement], right: Sequence[RingElement]) -> tuple[RingElement, ...]:
    if len(left) != len(right):
        raise RingProtocol1Error("vector dimensions differ")
    return tuple(a.add(b) for a, b in zip(left, right))


def _scale_ring(scalar: RingElement, values: Sequence[RingElement]) -> tuple[RingElement, ...]:
    return tuple(scalar.mul(value) for value in values)


def _flatten(rows: Sequence[Sequence[RingElement]]) -> tuple[RingElement, ...]:
    return tuple(element for row in rows for element in row)


def _sum_vectors(
    vectors: Sequence[Sequence[RingElement]],
    params,
    weights: Sequence[int | RingElement] | None = None,
) -> tuple[RingElement, ...]:
    """Sum equal-width ring vectors using scalar or ring weights."""
    if not vectors:
        raise RingProtocol1Error("cannot sum empty vectors")
    width = len(vectors[0])
    if width == 0 or any(len(vector) != width for vector in vectors):
        raise RingProtocol1Error("vector dimensions differ")
    coefficients: tuple[int | RingElement, ...] = (
        tuple(weights) if weights is not None else (1,) * len(vectors)
    )
    if len(coefficients) != len(vectors):
        raise RingProtocol1Error("weight dimensions differ")
    terms: list[tuple[RingElement, ...]] = []
    for vector, weight in zip(vectors, coefficients):
        if isinstance(weight, RingElement):
            if weight.params != params:
                raise RingProtocol1Error("ring weight parameter mismatch")
            terms.append(tuple(weight.mul(value) for value in vector))
        else:
            terms.append(tuple(value.scalar_mul(weight) for value in vector))
    return tuple(
        _sum_elements(tuple(row[index] for row in terms), params)
        for index in range(width)
    )


def _ring_one(params) -> RingElement:
    return RingElement.from_coeffs((1,) + (0,) * (params.n - 1), params)


def _ring_powers(base: RingElement, count: int) -> tuple[RingElement, ...]:
    if count <= 0:
        raise RingProtocol1Error("power count must be positive")
    powers = [_ring_one(base.params)]
    for _ in range(1, count):
        powers.append(powers[-1].mul(base))
    return tuple(powers)


def _l2_norm(elements: Sequence[RingElement]) -> Decimal:
    total = sum(
        coefficient * coefficient
        for element in elements
        for coefficient in centered_coefficients(element)
    )
    return Decimal(total).sqrt()


def _same_key_shape(left: HMCKey, right: HMCKey) -> bool:
    return (
        left.params == right.params
        and left.ring_rows == right.ring_rows
        and left.randomness_width == right.randomness_width
    )


def _check_opening(opening: Sequence[RingElement], key: HMCKey, label: str) -> tuple[RingElement, ...]:
    result = tuple(opening)
    if len(result) != key.randomness_width:
        raise RingProtocol1Error(f"{label} opening width mismatch")
    if any(value.params != key.params for value in result):
        raise RingProtocol1Error(f"{label} opening parameter mismatch")
    return result


def _check_bits(
    key: HMCKey,
    commitments: Sequence[Sequence[RingElement]],
    bits: Sequence[Sequence[RingElement]],
    openings: Sequence[Sequence[RingElement]],
) -> tuple[tuple[tuple[RingElement, ...], ...], int, int]:
    if len(commitments) != len(bits) or len(bits) != len(openings):
        raise RingProtocol1Error("bit commitment dimensions differ")
    if not bits or not bits[0]:
        raise RingProtocol1Error("bit witness cannot be empty")
    width = len(bits[0])
    normalized_bits = tuple(tuple(vector) for vector in bits)
    for index, (public, vector, opening) in enumerate(zip(commitments, normalized_bits, openings)):
        if len(vector) != width:
            raise RingProtocol1Error("bit vector widths differ")
        public_tuple = tuple(public)
        if len(public_tuple) != key.ring_rows:
            raise RingProtocol1Error("bit commitment row count mismatch")
        checked_opening = _check_opening(opening, key, f"bit[{index}]")
        if public_tuple != key.commit(vector, checked_opening):
            raise RingProtocol1Error(f"bit commitment {index} does not match witness")
        for bit in vector:
            coefficients = centered_coefficients(bit)
            if coefficients[0] not in (0, 1) or any(value != 0 for value in coefficients[1:]):
                raise RingProtocol1Error("bits must be constant ring polynomials equal to 0 or 1")
    return normalized_bits, len(normalized_bits), width


def _transcript_frame(*parts: bytes) -> bytes:
    output = bytearray(b"PQCT-PROTOCOL1-RING-V2")
    for part in parts:
        output.extend(len(part).to_bytes(8, "big"))
        output.extend(part)
    return bytes(output)


@dataclass(frozen=True)
class RingProtocol1Parameters:
    """Challenge and verifier bounds for the research transcript.

    Bounds are explicit policy inputs. They are not security parameters unless
    derived from the paper formulas and then checked against a concrete
    Module-SIS/LWE estimate.
    """

    challenge_weight: int
    challenge_coefficient_bound: int
    g_bound: int | Decimal
    zg_bound: int | Decimal
    zb_bound: int | Decimal
    max_vectors: int = 2
    challenge_domain: bytes = b"PQCT-PROTOCOL1-RING-CHALLENGE-V2"

    def __post_init__(self) -> None:
        if min(self.challenge_weight, self.challenge_coefficient_bound) <= 0:
            raise RingProtocol1Error("challenge parameters must be positive")
        if min(Decimal(self.g_bound), Decimal(self.zg_bound), Decimal(self.zb_bound)) <= 0:
            raise RingProtocol1Error("Protocol 1 bounds must be positive")
        if not 1 <= self.max_vectors <= 2:
            raise RingProtocol1Error("Gao Theorem 1 reference path supports S <= 2")
        if not self.challenge_domain or len(self.challenge_domain) > 220:
            raise RingProtocol1Error("challenge domain must contain 1..220 bytes")

    @classmethod
    def from_paper_bounds(
        cls,
        *,
        challenge_weight: int,
        challenge_coefficient_bound: int,
        B: int,
        p: int,
        k: int,
        m: int,
        d: int,
        phi1: Decimal,
        phi2: Decimal,
        max_vectors: int = 2,
    ) -> "RingProtocol1Parameters":
        """Build verifier bounds from Protocol 1's displayed formulas."""
        if min(B, p, k, m, d) <= 0 or phi1 <= 0 or phi2 <= 0:
            raise RingProtocol1Error("paper-bound inputs must be positive")
        t1 = Decimal(p) * Decimal(2 * challenge_weight * k).sqrt()
        t2 = Decimal(B * challenge_weight * p) * Decimal(3 * m * d).sqrt()
        g_bound = Decimal(2) * phi1 * t1 * Decimal(d).sqrt()
        zg_bound = Decimal(2) * phi2 * t2 * Decimal(m * d).sqrt()
        zb_bound = Decimal(2 * m * d) * phi2 * t2 * Decimal(challenge_weight * p + 1)
        return cls(
            challenge_weight,
            challenge_coefficient_bound,
            g_bound,
            zg_bound,
            zb_bound,
            max_vectors,
        )


@dataclass(frozen=True)
class RingProtocol1Proof:
    commitment_e: tuple[RingElement, ...]
    commitment_f: tuple[RingElement, ...]
    commitment_g: tuple[RingElement, ...]
    responses_g: tuple[tuple[RingElement, ...], ...]
    response_zg: tuple[RingElement, ...]
    response_zb: tuple[RingElement, ...]


def _derive_challenge(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    stage_commitments: Sequence[Sequence[RingElement]],
    params: RingProtocol1Parameters,
    *,
    stage: bytes,
    prior: Sequence[bytes] = (),
) -> RingElement:
    if not statement or not stage:
        raise RingProtocol1Error("statement and challenge stage cannot be empty")
    challenge_params = RingChallengeParameters(
        weight=params.challenge_weight,
        coefficient_bound=params.challenge_coefficient_bound,
        domain=params.challenge_domain + b"|" + stage,
    )
    commitments = tuple(tuple(row) for row in (*bit_commitments, *stage_commitments))
    bound_statement = _transcript_frame(
        statement,
        base_key.encode(),
        key_e.encode(),
        key_f.encode(),
        key_g.encode(),
        stage,
        *prior,
    )
    return derive_ring_challenge(
        bound_statement, base_key.params, challenge_params, commitments,
    ).element


def _derive_zeta(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    params: RingProtocol1Parameters,
) -> RingElement:
    return _derive_challenge(
        statement, base_key, key_e, key_f, key_g, bit_commitments, (), params,
        stage=b"zeta",
    )


def _derive_x(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    proof_commitments: Sequence[Sequence[RingElement]],
    zeta: RingElement,
    params: RingProtocol1Parameters,
) -> RingElement:
    return _derive_challenge(
        statement, base_key, key_e, key_f, key_g, bit_commitments,
        proof_commitments, params, stage=b"x", prior=(zeta.encode(),),
    )


def _check_key_shapes(base_key: HMCKey, key_e: HMCKey, key_f: HMCKey, key_g: HMCKey) -> None:
    if not (
        _same_key_shape(base_key, key_e)
        and _same_key_shape(base_key, key_f)
        and _same_key_shape(base_key, key_g)
    ):
        raise RingProtocol1Error(
            "all Protocol 1 commitment keys must share ring, row, and randomness shapes"
        )


def build_protocol1_ring_transcript(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    bits: Sequence[Sequence[RingElement]],
    openings: Sequence[Sequence[RingElement]],
    masks_t: Sequence[Sequence[RingElement]],
    mask_opening_e: Sequence[RingElement],
    mask_opening_f: Sequence[RingElement],
    mask_openings_t: Sequence[Sequence[RingElement]],
    params: RingProtocol1Parameters,
    *,
    zeta: RingElement | None = None,
    challenge_x: RingElement | None = None,
) -> RingProtocol1Proof:
    """Create the public equation transcript with caller-supplied masks.

    This is the exact public equation path, but it intentionally does not
    perform sampling or rejection. Use the sampled wrapper for an experiment.
    """
    _check_key_shapes(base_key, key_e, key_f, key_g)
    normalized_bits, count, width = _check_bits(base_key, bit_commitments, bits, openings)
    if count > params.max_vectors:
        raise RingProtocol1Error("unsupported vector count")
    masks = tuple(tuple(row) for row in masks_t)
    if len(masks) != count or any(len(row) != width for row in masks):
        raise RingProtocol1Error("mask t dimensions differ")
    if any(value.params != base_key.params for row in masks for value in row):
        raise RingProtocol1Error("mask t parameter mismatch")
    re = _check_opening(mask_opening_e, key_e, "r_e")
    rf = _check_opening(mask_opening_f, key_f, "r_f")
    rt = tuple(
        _check_opening(row, key_g, f"r_t[{index}]")
        for index, row in enumerate(mask_openings_t)
    )
    if len(rt) != count:
        raise RingProtocol1Error("r_t dimensions differ")

    e_message = tuple(
        masks[i][j].scalar_mul(
            1 - 2 * centered_coefficients(normalized_bits[i][j])[0]
        )
        for i in range(count)
        for j in range(width)
    )
    f_message = tuple(
        masks[i][j].mul(masks[i][j]).scalar_mul(-1)
        for i in range(count)
        for j in range(width)
    )
    if key_e.message_width != len(e_message) or key_f.message_width != len(f_message):
        raise RingProtocol1Error("E/F message width must equal S times bit width")
    if key_g.message_width != width:
        raise RingProtocol1Error("G message width must equal bit width")

    if zeta is None:
        zeta = _derive_zeta(
            statement, base_key, key_e, key_f, key_g, bit_commitments, params,
        )
    elif zeta.params != base_key.params:
        raise RingProtocol1Error("zeta parameter mismatch")
    zeta_powers = _ring_powers(zeta, count)
    g_message = _sum_vectors(masks, base_key.params, zeta_powers)
    g_opening = _sum_vectors(rt, base_key.params, zeta_powers)
    commitment_e = key_e.commit(e_message, re)
    commitment_f = key_f.commit(f_message, rf)
    commitment_g = key_g.commit(g_message, g_opening)
    x = challenge_x if challenge_x is not None else _derive_x(
        statement, base_key, key_e, key_f, key_g, bit_commitments,
        (commitment_e, commitment_f, commitment_g), zeta, params,
    )
    if x.params != base_key.params:
        raise RingProtocol1Error("x challenge parameter mismatch")

    responses_g = tuple(
        tuple(x.mul(normalized_bits[i][j]).add(masks[i][j]) for j in range(width))
        for i in range(count)
    )
    response_zg = _add(_scale_ring(x, re), rf)
    response_zb_by_index = tuple(
        _add(_scale_ring(x, openings[i]), rt[i])
        for i in range(count)
    )
    response_zb = _sum_vectors(response_zb_by_index, base_key.params, zeta_powers)

    if any(
        _l2_norm((value,)) > Decimal(params.g_bound)
        for row in responses_g
        for value in row
    ):
        raise RingProtocol1Error("g response norm exceeds bound")
    if _l2_norm(response_zg) > Decimal(params.zg_bound):
        raise RingProtocol1Error("z_g response norm exceeds bound")
    if _l2_norm(response_zb) > Decimal(params.zb_bound):
        raise RingProtocol1Error("z_b response norm exceeds bound")
    return RingProtocol1Proof(
        commitment_e, commitment_f, commitment_g,
        responses_g, response_zg, response_zb,
    )


# Backward-compatible name for the FS-derived equation prover.
prove_protocol1_ring = build_protocol1_ring_transcript


def verify_protocol1_ring(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    proof: RingProtocol1Proof,
    params: RingProtocol1Parameters,
    *,
    zeta: RingElement | None = None,
    challenge_x: RingElement | None = None,
) -> bool:
    """Verify Protocol 1's public equations and Euclidean response bounds."""
    try:
        _check_key_shapes(base_key, key_e, key_f, key_g)
        public = tuple(tuple(row) for row in bit_commitments)
        count = len(public)
        if count == 0 or count > params.max_vectors:
            return False
        if any(len(row) != base_key.ring_rows for row in public):
            return False
        width = len(proof.responses_g[0]) if proof.responses_g else 0
        if width == 0 or len(proof.responses_g) != count:
            return False
        if any(len(row) != width for row in proof.responses_g):
            return False
        if len(proof.response_zg) != key_e.randomness_width:
            return False
        if len(proof.response_zb) != key_g.randomness_width:
            return False
        if key_e.message_width != count * width or key_f.message_width != count * width:
            return False
        if key_g.message_width != width:
            return False

        if any(
            _l2_norm((value,)) > Decimal(params.g_bound)
            for row in proof.responses_g
            for value in row
        ):
            return False
        if _l2_norm(proof.response_zg) > Decimal(params.zg_bound):
            return False
        if _l2_norm(proof.response_zb) > Decimal(params.zb_bound):
            return False

        zeta = zeta if zeta is not None else _derive_zeta(
            statement, base_key, key_e, key_f, key_g, public, params,
        )
        if zeta.params != base_key.params:
            return False
        zeta_powers = _ring_powers(zeta, count)
        x = challenge_x if challenge_x is not None else _derive_x(
            statement, base_key, key_e, key_f, key_g, public,
            (proof.commitment_e, proof.commitment_f, proof.commitment_g),
            zeta, params,
        )
        if x.params != base_key.params:
            return False
        weighted_public = _sum_vectors(public, base_key.params, zeta_powers)
        weighted_g = _sum_vectors(proof.responses_g, base_key.params, zeta_powers)
        lhs_g = _add(_scale_ring(x, weighted_public), proof.commitment_g)
        rhs_g = key_g.commit(weighted_g, proof.response_zb)
        if lhs_g != rhs_g:
            return False

        x_one_minus_g = tuple(
            tuple(response.mul(x.sub(response)) for response in row)
            for row in proof.responses_g
        )
        e_message = _flatten(x_one_minus_g)
        lhs_e = _add(_scale_ring(x, proof.commitment_e), proof.commitment_f)
        rhs_e = key_e.commit(e_message, proof.response_zg)
        return lhs_e == rhs_e
    except (HMCError, RingProtocol1Error, EncodingError, TypeError, ValueError, OverflowError):
        return False


__all__ = [
    "RingProtocol1Error",
    "RingProtocol1Parameters",
    "RingProtocol1Proof",
    "build_protocol1_ring_transcript",
    "prove_protocol1_ring",
    "verify_protocol1_ring",
]
