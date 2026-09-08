"""Binary-relation extraction (Gao Appendix B equations 38-45)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .binary_protocol1_ring import RingProtocol1Parameters, RingProtocol1Proof
from .hmc import centered_coefficients
from .ring_commitment import RingElement

# --------------------------------------------------------------------------
# Existing entry point (kept unchanged): divided-difference of g_{i,j}(x).
# --------------------------------------------------------------------------


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


# --------------------------------------------------------------------------
# Equations (38)-(45): the "actual hard part" per docs/BINARY_RELATION.md.
#
# This section is a BOUNDED, EXECUTABLE ORACLE, not a knowledge extractor.
# It takes the honest witness (b_{i,j}, t_{i,j}) and the already-implemented
# E/F relaxed openings (e^{i,j}, s^{i,j}, from
# pqct.protocol1_extraction.extract_second_layer's opening_e/opening_f,
# flattened) as CALLER-SUPPLIED inputs, and mechanically checks that the
# paper's equations (39)-(45) hold for them. It does NOT derive b_{i,j} or
# t_{i,j} from ciphertexts/commitments; that would require the per-index
# unbatching of the zeta-aggregated eq.(38)/(40) that
# docs/BINARY_RELATION.md flags as not implemented anywhere in this
# codebase. Equations (38) and (40) are the ones that need that unbatched
# b^_{i,j}, and are therefore deliberately NOT claimed here -- see
# `equation_38_40_note` below.
#
# What IS checked here, precisely:
#   eq.(39)/(41): y*h_{i,j} = x*e^_{i,j} + s^_{i,j}, evaluated at each of
#     the three x-transcripts' own (x_k, g_k), reusing the same e^, s^
#     extracted once from the (x0, x1) pair -- this is the per-index,
#     third-transcript-consistency form of eq.(41) ("in Rq").
#   eq.(42)-(44): the *unreduced* (over R, not R_q) integer polynomial
#     identity obtained by substituting g_{i,j} = x*b_{i,j} + t_{i,j} into
#     h_{i,j} and eq.(41), for each of the three x_k. This gives one
#     degree-2-in-x row per transcript with a common quadratic-in-x
#     coefficient u = b_{i,j}*(yy - b_{i,j}), yy := y*y_zeta.
#   eq.(45): the Cramer's-rule corollary D*u = 0 in R, where
#     D = (x0-x1)(x0-x2)(x1-x2) is the Vandermonde factor. This is checked
#     directly (not merely inferred) as an independent arithmetic
#     cross-check on the same unreduced integers.
#
# Boundary (see also equation_38_40_note and BinaryEquationCheck fields):
#   D*u = 0 in R does not, by itself, prove b_{i,j} in {0, y*y_zeta} unless
#   R = Z[X]/(X^n+1) is known to have no zero divisors among the specific
#   elements involved (b_{i,j}, y, y_zeta are all "short" but R is not a
#   field/integral domain in general). This module reports the concrete
#   per-coefficient comparison (u == 0 exactly, and whether b_{i,j} equals
#   the zero polynomial or y*y_zeta exactly) but does NOT claim the
#   zero-divisor gap is closed. This mirrors the exact risk flagged in the
#   independent derivation referenced from docs/BINARY_RELATION.md.
# --------------------------------------------------------------------------


equation_38_40_note = (
    "Equations (38) and (40) aggregate over i with zeta powers "
    "(sum_i zeta^i * g_i) and require a per-index unbatching of the "
    "extracted t^_i / b^_i via the HMC bin-binding argument (paper text "
    "lines 2199-2211). That unbatching machinery does not exist in this "
    "codebase (see docs/BINARY_RELATION.md); this module does not "
    "implement or assume it. Only the E/F-side equations (39),(41), which "
    "are already per-(i,j) in the existing SecondLayerExtraction, and the "
    "downstream integer system (42)-(45) built from the true witness "
    "b_{i,j}, t_{i,j} (available to the harness, not extracted), are "
    "checked here."
)


class BinaryEquationError(ValueError):
    """Malformed input to the equations (38)-(45) oracle."""


def _zero_int(n: int) -> tuple[int, ...]:
    return (0,) * n


def _add_int(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    if len(left) != len(right):
        raise BinaryEquationError("integer polynomial widths differ")
    return tuple(a + b for a, b in zip(left, right))


def _sub_int(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    if len(left) != len(right):
        raise BinaryEquationError("integer polynomial widths differ")
    return tuple(a - b for a, b in zip(left, right))


def _scale_int(values: Sequence[int], scalar: int) -> tuple[int, ...]:
    return tuple(scalar * value for value in values)


def _mul_int(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    """Unreduced (mod nothing but X^n+1) multiplication in Z[X]/(X^n+1).

    This is the paper's "R" (not "R_q"): coefficients are not reduced mod
    q. Only the negacyclic wraparound X^n = -1 is applied, matching
    pqct.protocol1_family's integer trace convention.
    """
    if len(left) != len(right) or not left:
        raise BinaryEquationError("integer ring operands must have equal nonzero width")
    n = len(left)
    result = [0] * n
    for i, a in enumerate(left):
        if a == 0:
            continue
        for j, b in enumerate(right):
            index = i + j
            if index < n:
                result[index] += a * b
            else:
                result[index - n] -= a * b
    return tuple(result)


@dataclass(frozen=True)
class BinaryEquationCheck:
    """Result of mechanically checking equations (39)-(45) for one (i,j).

    Not a soundness proof; see the module-level boundary note above and
    `equation_38_40_note`.
    """

    row: int
    column: int
    equation_41_mod_q_ok: tuple[bool, bool, bool]
    """eq.(41), y*h_k = x_k*e^ + s^, checked mod q at each of the 3 transcripts."""
    equation_44_rows_ok: tuple[bool, bool, bool]
    """eq.(44)'s three rows, checked as unreduced integers (over R)."""
    vandermonde_factor: tuple[int, ...]
    """D = (x0-x1)(x0-x2)(x1-x2), unreduced, as a raw integer coefficient tuple."""
    quadratic_unknown: tuple[int, ...]
    """u = b_ij*(y*y_zeta - b_ij), unreduced, before multiplying by D."""
    equation_45_value: tuple[int, ...]
    """D*u, unreduced; the paper's eq.(45) claims this is the zero polynomial."""
    equation_45_holds: bool
    quadratic_unknown_is_zero: bool
    """True iff u itself (not merely D*u) is the zero polynomial."""
    witness_matches_zero: bool
    """True iff b_ij's centered coefficients are exactly the zero polynomial."""
    witness_matches_yy: bool
    """True iff b_ij's centered coefficients exactly equal y*y_zeta's."""

    @property
    def fully_consistent(self) -> bool:
        """All the mod-q and unreduced-integer checks this module performs pass.

        Does NOT by itself establish b_ij in {0, y*y_zeta}; see
        `witness_matches_zero` / `witness_matches_yy` and the module
        docstring's zero-divisor caveat.
        """
        return all(self.equation_41_mod_q_ok) and all(self.equation_44_rows_ok) and self.equation_45_holds


def verify_binary_relation_equations_38_45(
    x_challenges: Sequence[RingElement],
    g_responses: Sequence[RingElement],
    y: RingElement,
    y_zeta: RingElement,
    b_ij: RingElement,
    t_ij: RingElement,
    e_hat_ij: RingElement,
    s_hat_ij: RingElement,
    row: int,
    column: int,
) -> BinaryEquationCheck:
    """Bounded oracle for Gao equations (39)-(45), scoped per (row, column).

    Parameters
    ----------
    x_challenges: exactly 3 distinct ring elements (x0, x1, x2), the three
        accepting-transcript challenges from a second-layer family.
    g_responses: the 3 transcripts' g_{row,column}(x_k) values (public,
        e.g. ``proof.responses_g[row][column]`` for each of the 3 proofs).
    y: the second-layer relaxation x0 - x1, used to extract e_hat_ij/
        s_hat_ij (matches ``SecondLayerExtraction.first_delta`` when the
        pair (0,1) was used).
    y_zeta: the first-layer (zeta-side) relaxation factor.
    b_ij, t_ij: the TRUE witness bit and mask for this (row, column) --
        supplied by the harness, not extracted. See module docstring.
    e_hat_ij, s_hat_ij: the flattened-(row,column) entries of
        ``SecondLayerExtraction.opening_e.message`` /
        ``opening_f.message`` for the same transcript pair used for ``y``.

    Raises BinaryEquationError on malformed/mismatched input.
    """
    xs = tuple(x_challenges)
    gs = tuple(g_responses)
    if len(xs) != 3 or len(gs) != 3:
        raise BinaryEquationError("equations (39)-(45) require exactly 3 transcripts")
    params = y.params
    all_elements = xs + gs + (y, y_zeta, b_ij, t_ij, e_hat_ij, s_hat_ij)
    if any(element.params != params for element in all_elements):
        raise BinaryEquationError("parameter mismatch among equation (39)-(45) inputs")
    if len({x.encode() for x in xs}) != 3:
        raise BinaryEquationError("x challenges must be distinct")

    # eq.(39)/(41): y*h_k = x_k*e_hat + s_hat, mod q, at each transcript.
    equation_41_mod_q_ok = tuple(
        y.mul(g_k.mul(x_k.sub(g_k))) == x_k.mul(e_hat_ij).add(s_hat_ij)
        for x_k, g_k in zip(xs, gs)
    )

    # eq.(42)-(44): unreduced integer system, one row per transcript.
    #
    # The paper's closing statement (line 2273) is b_hat_{i,j} = y*y_zeta *
    # b_{i,j} for the TRUE bit b_{i,j} in {0,1} (b_hat is the value
    # appearing in eq.(38)/(40)'s "x*bhat_{i,j} + y*that_{i,j}" term, i.e.
    # what a real per-index unbatching extractor would recover). The
    # matching scaling for t is t_hat_{i,j} = y_zeta * t_{i,j} (both
    # picked up the first-layer y_zeta factor; b additionally carries the
    # second-layer y from y_zeta*y*b = Y*b). Getting this scaling wrong
    # (e.g. using y_zeta*b instead of y*y_zeta*b) silently breaks eq.(44)
    # even for a genuinely binary witness -- this was caught empirically
    # while building this oracle and is exactly the kind of sign/scope
    # risk flagged in docs/BINARY_RELATION.md.
    y_int = _centered(y)
    yzeta_int = _centered(y_zeta)
    yy_int = _mul_int(y_int, yzeta_int)  # Y = y * y_zeta
    b_true_int = _centered(b_ij)
    t_int_raw = _centered(t_ij)
    e_int = _centered(e_hat_ij)
    s_int = _centered(s_hat_ij)

    b_int = _mul_int(yy_int, b_true_int)  # b_hat = Y * b
    t_int = _mul_int(yzeta_int, t_int_raw)  # t_hat = y_zeta * t

    term_quad = _mul_int(b_int, _sub_int(yy_int, b_int))  # b_hat*(Y-b_hat)
    term_lin = _sub_int(
        _mul_int(y_int, _mul_int(t_int, _sub_int(yy_int, _scale_int(b_int, 2)))),
        _mul_int(_mul_int(yzeta_int, yzeta_int), _mul_int(y_int, e_int)),
    )  # y*t_hat*(Y-2*b_hat) - y_zeta^2*y*e_hat
    term_const = _add_int(
        _mul_int(_mul_int(y_int, y_int), _mul_int(t_int, t_int)),
        _mul_int(_mul_int(yzeta_int, yzeta_int), _mul_int(y_int, s_int)),
    )  # y^2*t_hat^2 + y_zeta^2*y*s_hat
    term_const = _scale_int(term_const, -1)

    equation_44_rows_ok = []
    x_ints = tuple(_centered(x_k) for x_k in xs)
    for x_int in x_ints:
        row_value = _sub_int(
            _add_int(
                _mul_int(_mul_int(x_int, x_int), term_quad),
                _mul_int(x_int, term_lin),
            ),
            term_const,
        )
        equation_44_rows_ok.append(row_value == _zero_int(params.n))

    # eq.(45): D*u = 0, D the Vandermonde factor, checked independently.
    d01 = _sub_int(x_ints[0], x_ints[1])
    d02 = _sub_int(x_ints[0], x_ints[2])
    d12 = _sub_int(x_ints[1], x_ints[2])
    vandermonde_factor = _mul_int(_mul_int(d01, d02), d12)
    equation_45_value = _mul_int(vandermonde_factor, term_quad)
    zero = _zero_int(params.n)

    return BinaryEquationCheck(
        row=row,
        column=column,
        equation_41_mod_q_ok=equation_41_mod_q_ok,
        equation_44_rows_ok=tuple(equation_44_rows_ok),
        vandermonde_factor=vandermonde_factor,
        quadratic_unknown=term_quad,
        equation_45_value=equation_45_value,
        equation_45_holds=(equation_45_value == zero),
        quadratic_unknown_is_zero=(term_quad == zero),
        witness_matches_zero=(b_int == zero),
        witness_matches_yy=(b_int == yy_int),
    )


__all__ = [
    "BinaryEquationCheck",
    "BinaryEquationError",
    "BinaryRelationError",
    "BinaryWitnessCheck",
    "equation_38_40_note",
    "extract_binary_witness_row",
    "verify_binary_relation_equations_38_45",
]
