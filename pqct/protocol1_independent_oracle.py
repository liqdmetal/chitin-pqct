"""Structurally independent Protocol 1 equation oracle.

This module deliberately operates on raw integer coefficient tuples. It does not
import HMCKey, RingElement, or the Protocol 1 prover/verifier. Its purpose is to
build and check hand-constructed interactive transcripts against the local ring
implementation, exposing mirrored-formula bugs.

It implements the public equations only. It does not derive Fiat--Shamir
challenges, sample the paper's distributions, perform rejection sampling, or
make a security claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .independent_oracle import matrix_commit, negacyclic_mul

Poly = tuple[int, ...]
Vector = tuple[Poly, ...]
Matrix = tuple[tuple[Poly, ...], ...]


class IndependentProtocol1Error(ValueError):
    """Malformed raw oracle input."""


def _mod_poly(values: Sequence[int], q: int) -> Poly:
    return tuple(int(value) % q for value in values)


def _add(left: Poly, right: Poly, q: int) -> Poly:
    if len(left) != len(right):
        raise IndependentProtocol1Error("polynomial widths differ")
    return _mod_poly((a + b for a, b in zip(left, right)), q)


def _sub(left: Poly, right: Poly, q: int) -> Poly:
    if len(left) != len(right):
        raise IndependentProtocol1Error("polynomial widths differ")
    return _mod_poly((a - b for a, b in zip(left, right)), q)


def _scale(value: Poly, scalar: int, q: int) -> Poly:
    return _mod_poly((scalar * coefficient for coefficient in value), q)


def _mul(left: Poly, right: Poly, q: int) -> Poly:
    return negacyclic_mul(left, right, q)


def _zero(n: int) -> Poly:
    return (0,) * n


def _one(n: int) -> Poly:
    return (1,) + (0,) * (n - 1)


def _vector_add(left: Sequence[Poly], right: Sequence[Poly], q: int) -> Vector:
    if len(left) != len(right):
        raise IndependentProtocol1Error("vector widths differ")
    return tuple(_add(a, b, q) for a, b in zip(left, right))


def _vector_scale(scalar: Poly, values: Sequence[Poly], q: int) -> Vector:
    return tuple(_mul(scalar, value, q) for value in values)


def _powers(base: Poly, count: int, q: int) -> tuple[Poly, ...]:
    if count <= 0:
        raise IndependentProtocol1Error("power count must be positive")
    result = [_one(len(base))]
    for _ in range(1, count):
        result.append(_mul(result[-1], base, q))
    return tuple(result)


def _weighted(rows: Sequence[Sequence[Poly]], zeta: Poly, q: int) -> Vector:
    if not rows or not rows[0]:
        raise IndependentProtocol1Error("cannot aggregate empty rows")
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise IndependentProtocol1Error("row widths differ")
    n = len(zeta)
    total = [_zero(n) for _ in range(width)]
    for power, row in zip(_powers(zeta, len(rows), q), rows):
        for index, value in enumerate(row):
            total[index] = _add(total[index], _mul(power, value, q), q)
    return tuple(total)


def _flatten(rows: Sequence[Sequence[Poly]]) -> Vector:
    return tuple(value for row in rows for value in row)


def _check_vector(values: Sequence[Poly], n: int, label: str) -> Vector:
    result = tuple(tuple(value) for value in values)
    if any(len(value) != n for value in result):
        raise IndependentProtocol1Error(f"{label} polynomial width differs")
    return result


@dataclass(frozen=True)
class RawHMCKey:
    """Raw coefficient-tuple HMC key used only by the independent oracle."""

    G_r: Matrix
    G_m: Matrix
    q: int

    def __post_init__(self) -> None:
        if self.q <= 2 or not self.G_r or not self.G_r[0] or not self.G_m:
            raise IndependentProtocol1Error("invalid raw HMC key")
        if len(self.G_r) != len(self.G_m):
            raise IndependentProtocol1Error("raw key row dimensions differ")
        random_width = len(self.G_r[0])
        message_width = len(self.G_m[0])
        n = len(self.G_r[0][0])
        if any(len(row) != random_width for row in self.G_r):
            raise IndependentProtocol1Error("raw randomness matrix is ragged")
        if any(len(row) != message_width for row in self.G_m):
            raise IndependentProtocol1Error("raw message matrix is ragged")
        if any(
            len(value) != n
            for matrix in (self.G_r, self.G_m)
            for row in matrix
            for value in row
        ):
            raise IndependentProtocol1Error("raw key polynomial dimensions differ")

    @property
    def n(self) -> int:
        return len(self.G_r[0][0])

    @property
    def ring_rows(self) -> int:
        return len(self.G_r)

    @property
    def randomness_width(self) -> int:
        return len(self.G_r[0])

    @property
    def message_width(self) -> int:
        return len(self.G_m[0])

    def commit(self, message: Sequence[Poly], randomness: Sequence[Poly]) -> Vector:
        if len(message) != self.message_width or len(randomness) != self.randomness_width:
            raise IndependentProtocol1Error("raw opening dimensions differ")
        _check_vector(message, self.n, "message")
        _check_vector(randomness, self.n, "randomness")
        return matrix_commit(self.G_r, self.G_m, randomness, message, self.q)


@dataclass(frozen=True)
class IndependentProtocol1Proof:
    commitment_e: Vector
    commitment_f: Vector
    commitment_g: Vector
    responses_g: tuple[Vector, ...]
    response_zg: Vector
    response_zb: Vector


@dataclass(frozen=True)
class IndependentProtocol1Transcript:
    bit_commitments: tuple[Vector, ...]
    proof: IndependentProtocol1Proof
    zeta: Poly
    x: Poly


def build_independent_transcript(
    base_key: RawHMCKey,
    key_e: RawHMCKey,
    key_f: RawHMCKey,
    key_g: RawHMCKey,
    bits: Sequence[Sequence[Poly]],
    openings: Sequence[Sequence[Poly]],
    masks_t: Sequence[Sequence[Poly]],
    mask_opening_e: Sequence[Poly],
    mask_opening_f: Sequence[Poly],
    mask_openings_t: Sequence[Sequence[Poly]],
    zeta: Poly,
    x: Poly,
) -> IndependentProtocol1Transcript:
    """Build Protocol 1 directly from raw tuples and published equations."""
    if base_key.q != key_e.q or base_key.q != key_f.q or base_key.q != key_g.q:
        raise IndependentProtocol1Error("commitment moduli differ")
    if not bits or len(bits) != len(openings) or len(bits) != len(masks_t):
        raise IndependentProtocol1Error("witness row dimensions differ")
    count = len(bits)
    width = len(bits[0])
    if width == 0 or any(len(row) != width for row in bits):
        raise IndependentProtocol1Error("bit widths differ")
    if len(mask_openings_t) != count:
        raise IndependentProtocol1Error("r_t row count differs")
    if len(zeta) != base_key.n or len(x) != base_key.n:
        raise IndependentProtocol1Error("challenge polynomial width differs")
    zeta = _mod_poly(zeta, base_key.q)
    x = _mod_poly(x, base_key.q)

    bit_rows = []
    for row in bits:
        checked = _check_vector(row, base_key.n, "bit")
        for bit in checked:
            if bit[0] % base_key.q not in (0, 1) or any(coefficient % base_key.q for coefficient in bit[1:]):
                raise IndependentProtocol1Error("bit is not a constant 0/1 polynomial")
        bit_rows.append(checked)
    opening_rows = tuple(_check_vector(row, base_key.n, "opening") for row in openings)
    mask_rows = tuple(_check_vector(row, base_key.n, "t mask") for row in masks_t)
    rt_rows = tuple(_check_vector(row, base_key.n, "r_t") for row in mask_openings_t)
    re = _check_vector(mask_opening_e, base_key.n, "r_e")
    rf = _check_vector(mask_opening_f, base_key.n, "r_f")
    if any(len(row) != base_key.randomness_width for row in opening_rows + rt_rows):
        raise IndependentProtocol1Error("opening width differs")
    if len(re) != key_e.randomness_width or len(rf) != key_f.randomness_width:
        raise IndependentProtocol1Error("E/F opening width differs")
    if any(len(row) != key_g.randomness_width for row in rt_rows):
        raise IndependentProtocol1Error("G opening width differs")
    if key_e.message_width != count * width or key_f.message_width != count * width:
        raise IndependentProtocol1Error("E/F message width differs")
    if key_g.message_width != width:
        raise IndependentProtocol1Error("G message width differs")

    bit_commitments = tuple(
        base_key.commit(row, opening)
        for row, opening in zip(bit_rows, opening_rows)
    )
    e_message = tuple(
        _scale(mask_rows[i][j], 1 - 2 * (bit_rows[i][j][0] % base_key.q), base_key.q)
        for i in range(count)
        for j in range(width)
    )
    f_message = tuple(
        _scale(_mul(mask_rows[i][j], mask_rows[i][j], base_key.q), -1, base_key.q)
        for i in range(count)
        for j in range(width)
    )
    powers = _powers(zeta, count, base_key.q)
    g_message = _weighted(mask_rows, zeta, base_key.q)
    g_opening = _weighted(rt_rows, zeta, base_key.q)
    commitment_e = key_e.commit(e_message, re)
    commitment_f = key_f.commit(f_message, rf)
    commitment_g = key_g.commit(g_message, g_opening)

    responses_g = tuple(
        tuple(_add(_mul(x, bit_rows[i][j], base_key.q), mask_rows[i][j], base_key.q) for j in range(width))
        for i in range(count)
    )
    response_zg = _vector_add(_vector_scale(x, re, base_key.q), rf, base_key.q)
    response_zb_rows = tuple(
        _vector_add(_vector_scale(x, opening_rows[i], base_key.q), rt_rows[i], base_key.q)
        for i in range(count)
    )
    response_zb = _weighted(response_zb_rows, zeta, base_key.q)
    proof = IndependentProtocol1Proof(
        commitment_e, commitment_f, commitment_g,
        responses_g, response_zg, response_zb,
    )
    return IndependentProtocol1Transcript(bit_commitments, proof, zeta, x)


def verify_independent_transcript(
    base_key: RawHMCKey,
    key_e: RawHMCKey,
    key_f: RawHMCKey,
    key_g: RawHMCKey,
    transcript: IndependentProtocol1Transcript,
) -> bool:
    """Verify both Protocol 1 equations using only raw tuple arithmetic."""
    try:
        public = transcript.bit_commitments
        proof = transcript.proof
        count = len(public)
        if count == 0 or len(proof.responses_g) != count:
            return False
        width = len(proof.responses_g[0])
        if width == 0 or any(len(row) != width for row in proof.responses_g):
            return False
        powers = _powers(transcript.zeta, count, base_key.q)
        weighted_public = _weighted(public, transcript.zeta, base_key.q)
        weighted_g = _weighted(proof.responses_g, transcript.zeta, base_key.q)
        lhs_g = _vector_add(
            _vector_scale(transcript.x, weighted_public, base_key.q),
            proof.commitment_g,
            base_key.q,
        )
        if lhs_g != key_g.commit(weighted_g, proof.response_zb):
            return False
        quadratic = tuple(
            _mul(value, _sub(transcript.x, value, base_key.q), base_key.q)
            for row in proof.responses_g
            for value in row
        )
        lhs_e = _vector_add(
            _vector_scale(transcript.x, proof.commitment_e, base_key.q),
            proof.commitment_f,
            base_key.q,
        )
        return lhs_e == key_e.commit(quadratic, proof.response_zg)
    except (IndependentProtocol1Error, TypeError, ValueError, IndexError):
        return False


__all__ = [
    "IndependentProtocol1Error",
    "IndependentProtocol1Proof",
    "IndependentProtocol1Transcript",
    "RawHMCKey",
    "build_independent_transcript",
    "verify_independent_transcript",
]
