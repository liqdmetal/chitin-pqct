"""Two-transcript extraction: what it can and cannot recover, honestly.

MOTIVATION
----------
`pqct/fiat_shamir_framework.py` shows the forking loss is (t-1)*log2(Q), so
extracting from t=2 transcripts instead of t=3 is worth 64 bits at
Q = 2^64. That is the single largest tractable lever on the Fiat-Shamir
budget, so it is worth establishing precisely what 2 transcripts give.

THE ALGEBRA
-----------
g(x) = x*b + t is linear in x, with two unknowns (b, t). Two transcripts
give two equations:

    g0 = x0*b + t
    g1 = x1*b + t

Subtracting:     y*b  = g0 - g1        with y = x0 - x1
Cross-multiplying: -y*t = x1*g0 - x0*g1

So BOTH relaxed values are recoverable from two transcripts. The system is
exactly determined; nothing is left over.

WHAT IS LOST, AND WHY IT MATTERS
--------------------------------
Exactly determined means NO REDUNDANCY, and that has a concrete
consequence: any pair (g0, g1) whatsoever is consistent with some (b, t).
Solve the 2x2 system and you always get an answer. There is no residual
equation left to check, so a prover whose responses are NOT affine in x is
undetectable from two transcripts.

Concretely, `verify_two_transcript_consistency` below can only re-derive
what it was given -- it is a tautology, and it is written to say so rather
than to look like a check. The third transcript supplies the first genuinely
falsifiable constraint:

    (x1 - x2)*(g0 - g1) == (x0 - x1)*(g1 - g2)

This module therefore does NOT justify claiming the 64 bits back. It
establishes the opposite, which is the useful result: 2-transcript
extraction recovers the relaxed witness but cannot enforce the binary
relation, so soundness at t=2 rests on the commitment binding alone rather
than on any transcript-level check.

WHAT WOULD ACTUALLY BUY THE 64 BITS
-----------------------------------
Two routes, both requiring work outside this module:
  1. Show the binary relation is enforced by the E/F commitment equations
     alone (which the verifier checks on EVERY transcript), so no
     cross-transcript consistency is needed. If true, t=2 suffices and the
     saving is real. `binary_relation_source` records that this is
     unresolved.
  2. Use a challenge set where a single challenge already pins the relation
     (e.g. larger p with a soundness amplification argument), trading
     challenge-space size for transcript count.

Neither is attempted here. The module's contribution is to stop the 64-bit
saving from being assumed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hmc import centered_coefficients
from .ring_commitment import RingElement
from .three_transcript_extraction import (
    ThreeTranscriptError,
    check_relaxed_binary,
    extract_relaxed_witness,
)


@dataclass(frozen=True)
class TwoTranscriptExtraction:
    """Relaxed witness from exactly two transcripts, with honest limits."""

    row: int
    column: int
    relaxation: RingElement
    relaxed_bit: RingElement
    relaxed_mask: RingElement
    binary_ok: bool

    @property
    def relaxed_bit_coeffs(self) -> tuple:
        return centered_coefficients(self.relaxed_bit)

    @property
    def relaxed_mask_coeffs(self) -> tuple:
        return centered_coefficients(self.relaxed_mask)

    @property
    def affine_check_available(self) -> bool:
        """Always False: two points cannot test affineness.

        Exposed as a property so callers cannot mistake the absence of a
        failure for the presence of a check.
        """
        return False

    def summary(self) -> dict:
        return {
            "row": self.row,
            "column": self.column,
            "binary_ok": self.binary_ok,
            "affine_check_available": self.affine_check_available,
            "limitation": (
                "the 2x2 system is exactly determined, so ANY response pair "
                "yields some (b,t); non-affine provers are undetectable "
                "without a third transcript"
            ),
        }


def extract_from_two_transcripts(
    challenges, proofs, row: int, column: int
) -> TwoTranscriptExtraction:
    """Recover (y*b, -y*t) from two transcripts on distinct challenges."""
    challenge_tuple = tuple(challenges)
    proof_tuple = tuple(proofs)
    if len(challenge_tuple) != 2 or len(proof_tuple) != 2:
        raise ThreeTranscriptError("exactly two transcripts are required")
    params = challenge_tuple[0].params
    if any(c.params != params for c in challenge_tuple):
        raise ThreeTranscriptError("challenge parameter mismatch")
    if challenge_tuple[0].encode() == challenge_tuple[1].encode():
        raise ThreeTranscriptError(
            "challenges must be distinct: y = 0 makes extraction vacuous"
        )
    for proof in proof_tuple:
        if row >= len(proof.responses_g) or column >= len(proof.responses_g[row]):
            raise ThreeTranscriptError("row/column outside the response grid")

    witness = extract_relaxed_witness(
        challenge_tuple, proof_tuple, row, column, 0, 1
    )
    return TwoTranscriptExtraction(
        row=row,
        column=column,
        relaxation=witness.relaxation,
        relaxed_bit=witness.relaxed_bit,
        relaxed_mask=witness.relaxed_mask,
        binary_ok=check_relaxed_binary(witness),
    )


def verify_two_transcript_consistency(
    challenges, proofs, row: int, column: int
) -> bool:
    """TAUTOLOGY -- returns True for any well-formed input. Deliberately so.

    There is no cross-transcript constraint at t=2: the extracted (y*b,
    -y*t) reproduce g0 and g1 by construction, because they were SOLVED from
    them. This function exists to make that emptiness explicit and testable,
    so nobody mistakes "the check passed" for evidence.

    Use `pqct.three_transcript_extraction.check_cross_consistency` for a
    constraint that can actually fail.
    """
    extraction = extract_from_two_transcripts(challenges, proofs, row, column)
    x0, x1 = tuple(challenges)
    g0 = proofs[0].responses_g[row][column]
    g1 = proofs[1].responses_g[row][column]

    # y*g0 = x0*(y*b) + (y*t) and y*g1 = x1*(y*b) + (y*t), where the module
    # returns -y*t, hence the subtraction. Both hold identically.
    y = extraction.relaxation
    y_times_t = RingElement.zero(y.params).sub(extraction.relaxed_mask)
    left0 = y.mul(g0)
    right0 = x0.mul(extraction.relaxed_bit).add(y_times_t)
    left1 = y.mul(g1)
    right1 = x1.mul(extraction.relaxed_bit).add(y_times_t)
    return left0 == right0 and left1 == right1


def binary_relation_source() -> dict:
    """Where binary-ness would have to come from if t=2 were used.

    Returns a structured statement of the open question rather than a
    verdict, because the answer determines whether the 64-bit forking saving
    is real and it has NOT been determined.
    """
    return {
        "question": (
            "Is the binary relation b in {0,1} enforced by the per-transcript "
            "E/F commitment equations alone, or does it require "
            "cross-transcript consistency?"
        ),
        "if_per_transcript": (
            "t=2 suffices, forking loss drops from (t-1)*log2(Q)=2*log2(Q) "
            "to log2(Q), recovering 64 bits at Q=2^64."
        ),
        "if_cross_transcript": (
            "t=3 is required and the 64 bits cannot be recovered this way."
        ),
        "status": "UNRESOLVED -- needs a lattice/ZK cryptographer",
        "evidence_available": (
            "The verifier checks x*commitment_e + commitment_f == "
            "Com(g*(x-g); z_g) on EVERY transcript "
            "(pqct/binary_protocol1_ring.py), which is a per-transcript "
            "statement about g*(x-g). Whether that pins b to a bit, or only "
            "pins it up to the relaxation factor, is exactly the open part."
        ),
        "forking_loss_bits_at_2_64": {"t=2": 64.0, "t=3": 128.0},
    }


__all__ = [
    "TwoTranscriptExtraction",
    "binary_relation_source",
    "extract_from_two_transcripts",
    "verify_two_transcript_consistency",
]
