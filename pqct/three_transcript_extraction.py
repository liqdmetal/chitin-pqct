"""Three-transcript binary-witness extraction (closes a standing item).

WHAT TWO TRANSCRIPTS GIVE, AND WHY IT IS NOT ENOUGH
---------------------------------------------------
The public response is g_{i,j}(x) = x*b_{i,j} + t_{i,j}, linear in x. From
two accepting transcripts (x0, g0), (x1, g1) the divided difference gives

    B_01 = g0 - g1 = (x0 - x1) * b        i.e. a RELAXED bit y*b, y = x0-x1

and nothing else. The mask t stays hidden, and -- more importantly -- there
is NO redundancy: any pair of values (g0, g1) whatsoever is consistent with
SOME line, so a cheating prover who does not use a linear g cannot be
detected from two points. Two points always fit a line.

WHAT THREE TRANSCRIPTS ADD
--------------------------
Three points on a claimed line are overdetermined (2 unknowns, 3 equations),
which buys three things this module implements, all WITHOUT ever inverting a
challenge difference (the ring has zero divisors; inversion is unavailable):

1. RELAXED MASK. Cross-multiplying two transcripts isolates t:
       x1*g0 - x0*g1 = x1*(x0*b + t) - x0*(x1*b + t) = (x1 - x0) * t
   so we recover (x1-x0)*t -- the mask, not just the bit. Two transcripts
   suffice for this algebraically, but it is only *meaningful* alongside the
   consistency check below, since otherwise there is no evidence the g's
   came from a common (b, t) at all.

2. CROSS-CONSISTENCY (the real gain). For a genuine line through all three
   points, this ring identity must hold:
       (x1 - x2) * (g0 - g1)  ==  (x0 - x1) * (g1 - g2)
   Both sides equal (x1-x2)(x0-x1)*b. It is an identity in R_q with no
   division, and it FAILS for responses that are not affine in x. This is
   what detects a prover whose three responses do not share one witness.

3. BINARY-NESS ON THE RELAXED VALUE. With B = y*b and b in {0,1}:
       B * (y - B) = y*b * y*(1-b) = y^2 * b*(1-b) = 0
   so `B*(y*1 - B) == 0` in R_q is a bit-check on the EXTRACTED relaxed
   value, again inversion-free. A relaxed opening of a non-bit fails it.

HONEST SCOPE
------------
This is a bounded EXTRACTION AND CONSISTENCY oracle, not a proof of
knowledge soundness. It shows that three accepting transcripts yield a
relaxed (b, t) pair satisfying the paper's relations, and that specific
cheating strategies are caught. It does not prove that every accepting
adversary can be rewound into three such transcripts (that is the
Fiat-Shamir/QROM item), nor that the relaxation factor y is benign for the
downstream binding argument.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hmc import centered_coefficients
from .ring_commitment import RingElement


class ThreeTranscriptError(ValueError):
    """Raised on malformed three-transcript extraction input."""


def _one(params) -> RingElement:
    """The ring's multiplicative identity."""
    return RingElement.from_coeffs((1,) + (0,) * (params.n - 1), params)


@dataclass(frozen=True)
class RelaxedWitness:
    """A relaxed (bit, mask) pair extracted from a transcript pair.

    `relaxation` is the challenge difference y that scales both: the values
    open y*b and y*t, NOT b and t. Reporting it explicitly keeps the
    relaxation visible instead of letting it be mistaken for an exact
    opening.
    """

    row: int
    column: int
    pair: tuple
    relaxation: RingElement
    relaxed_bit: RingElement
    relaxed_mask: RingElement

    @property
    def relaxed_bit_coeffs(self) -> tuple:
        return centered_coefficients(self.relaxed_bit)

    @property
    def relaxed_mask_coeffs(self) -> tuple:
        return centered_coefficients(self.relaxed_mask)


@dataclass(frozen=True)
class ThreeTranscriptExtraction:
    """Extraction from all three transcripts, with every cross-check."""

    row: int
    column: int
    witnesses: tuple
    cross_consistent: bool
    binary_ok: tuple
    pairwise_bits_agree: bool

    @property
    def accepted(self) -> bool:
        return (
            self.cross_consistent
            and all(self.binary_ok)
            and self.pairwise_bits_agree
        )

    def summary(self) -> dict:
        return {
            "row": self.row,
            "column": self.column,
            "pairs": [w.pair for w in self.witnesses],
            "cross_consistent": self.cross_consistent,
            "binary_ok": list(self.binary_ok),
            "pairwise_bits_agree": self.pairwise_bits_agree,
            "accepted": self.accepted,
        }


def extract_relaxed_witness(
    challenges, proofs, row: int, column: int, first: int, second: int
) -> RelaxedWitness:
    """Relaxed (y*b, y*t) from transcripts `first` and `second`.

        y      = x_first - x_second
        y*b    = g_first - g_second
        (-y)*t = x_first*g_second - x_second*g_first

    The mask identity is written so its scale is exactly -y, matching the
    bit's +y up to sign; callers must not assume both share a sign.
    """
    x_a, x_b = challenges[first], challenges[second]
    g_a = proofs[first].responses_g[row][column]
    g_b = proofs[second].responses_g[row][column]
    params = x_a.params
    for element in (x_b, g_a, g_b):
        if element.params != params:
            raise ThreeTranscriptError("ring parameter mismatch")

    relaxation = x_a.sub(x_b)
    relaxed_bit = g_a.sub(g_b)
    # x_a*g_b - x_b*g_a = (x_a - x_b)*t ... expand: x_a(x_b b + t) is NOT
    # this; compute directly the combination that cancels b:
    #   x_b*g_a - x_a*g_b = x_b(x_a b + t) - x_a(x_b b + t) = (x_b - x_a) t
    relaxed_mask = x_b.mul(g_a).sub(x_a.mul(g_b))
    return RelaxedWitness(
        row=row, column=column, pair=(first, second),
        relaxation=relaxation, relaxed_bit=relaxed_bit,
        relaxed_mask=relaxed_mask,
    )


def check_cross_consistency(challenges, proofs, row: int, column: int) -> bool:
    """(x1-x2)*(g0-g1) == (x0-x1)*(g1-g2), an inversion-free line test.

    Holds iff the three responses are affine in x with a common slope, i.e.
    iff they could have come from one (b, t). Fails for non-affine responses.
    """
    x0, x1, x2 = challenges[0], challenges[1], challenges[2]
    g0 = proofs[0].responses_g[row][column]
    g1 = proofs[1].responses_g[row][column]
    g2 = proofs[2].responses_g[row][column]
    left = x1.sub(x2).mul(g0.sub(g1))
    right = x0.sub(x1).mul(g1.sub(g2))
    return left == right


def check_relaxed_binary(witness: RelaxedWitness) -> bool:
    """B*(y - B) == 0, i.e. y^2*b*(1-b) == 0. True iff the relaxed value
    opens a bit (inversion-free)."""
    B = witness.relaxed_bit
    y = witness.relaxation
    return B.mul(y.sub(B)) == RingElement.zero(B.params)


def check_pairwise_bits_agree(witnesses) -> bool:
    """All three pairwise relaxed bits must describe the SAME b.

    y_ab*b and y_cd*b cannot be compared directly (different scales), but
    cross-multiplication removes the scales without division:
        y_cd * (y_ab * b)  ==  y_ab * (y_cd * b)
    """
    items = tuple(witnesses)
    for index, first in enumerate(items):
        for second in items[index + 1:]:
            left = second.relaxation.mul(first.relaxed_bit)
            right = first.relaxation.mul(second.relaxed_bit)
            if left != right:
                return False
    return True


def extract_from_three_transcripts(
    challenges, proofs, row: int, column: int
) -> ThreeTranscriptExtraction:
    """Full three-transcript extraction with all cross-checks.

    Requires exactly three transcripts with DISTINCT challenges: repeating a
    challenge collapses a pair's relaxation y to zero, which makes every
    check vacuously true (0 == 0) and would silently accept anything.
    """
    challenge_tuple = tuple(challenges)
    proof_tuple = tuple(proofs)
    if len(challenge_tuple) != 3 or len(proof_tuple) != 3:
        raise ThreeTranscriptError("exactly three transcripts are required")
    params = challenge_tuple[0].params
    if any(c.params != params for c in challenge_tuple):
        raise ThreeTranscriptError("challenge parameter mismatch")
    encoded = {c.encode() for c in challenge_tuple}
    if len(encoded) != 3:
        raise ThreeTranscriptError(
            "challenges must be distinct: a repeated challenge zeroes the "
            "relaxation and makes every check vacuous"
        )
    for proof in proof_tuple:
        if row >= len(proof.responses_g) or column >= len(proof.responses_g[row]):
            raise ThreeTranscriptError("row/column outside the response grid")

    witnesses = tuple(
        extract_relaxed_witness(challenge_tuple, proof_tuple, row, column, a, b)
        for a, b in ((0, 1), (0, 2), (1, 2))
    )
    return ThreeTranscriptExtraction(
        row=row,
        column=column,
        witnesses=witnesses,
        cross_consistent=check_cross_consistency(
            challenge_tuple, proof_tuple, row, column
        ),
        binary_ok=tuple(check_relaxed_binary(w) for w in witnesses),
        pairwise_bits_agree=check_pairwise_bits_agree(witnesses),
    )


def extract_all_rows(challenges, proofs) -> tuple:
    """Extract every (row, column) position in the response grid."""
    proof_tuple = tuple(proofs)
    if not proof_tuple:
        raise ThreeTranscriptError("no transcripts supplied")
    rows = len(proof_tuple[0].responses_g)
    results = []
    for row in range(rows):
        width = len(proof_tuple[0].responses_g[row])
        for column in range(width):
            results.append(
                extract_from_three_transcripts(challenges, proofs, row, column)
            )
    return tuple(results)


__all__ = [
    "RelaxedWitness",
    "ThreeTranscriptError",
    "ThreeTranscriptExtraction",
    "check_cross_consistency",
    "check_pairwise_bits_agree",
    "check_relaxed_binary",
    "extract_all_rows",
    "extract_from_three_transcripts",
    "extract_relaxed_witness",
]
