"""Multi-round Fiat-Shamir analysis -- and why the earlier numbers were too kind.

THE STRUCTURAL FINDING
----------------------
The Fiat-Shamir framework in `pqct/fiat_shamir_framework.py` charged a QROM
loss of 2*log2(Q) and a forking loss of (t-1)*log2(Q) with t=3. Both assumed
a THREE-MOVE (single-challenge) Sigma protocol. Reading the actual code, that
is wrong:

    _derive_zeta(statement, keys, bit_commitments, (),        stage=b"zeta")
    _derive_x   (statement, keys, bit_commitments, (E,F,G),   stage=b"x",
                 prior=(zeta,))

zeta is derived from the FIRST message (the bit commitments) and x from the
SECOND (E, F, G). So the interactive protocol is

    P -> V : bit commitments B_i          (first message)
    V -> P : zeta                         (challenge 1)
    P -> V : E, F, G                      (second message)
    V -> P : x                            (challenge 2)
    P -> V : responses g, z_g, z_b        (third message)

which is a FIVE-MOVE, TWO-CHALLENGE protocol. The paper's Protocol 1 as
printed (steps 5-11) shows only x, because the zeta-power aggregation is
presented as a fixed amortisation weight rather than a verifier move. Once
zeta is derived by hashing -- and the prover CHOOSES the bit commitments, so
it can grind them -- zeta is adaptively influenced and must be treated as a
genuine Fiat-Shamir round.

WHY THIS MAKES THINGS WORSE, TWICE
----------------------------------
1. EXTRACTION NEEDS A TREE, NOT A LINE. With two challenges, special
   soundness is not "3 transcripts on distinct x". It is a TREE: several
   zeta branches, each with several x leaves. `pqct/protocol1_family.py`
   already builds exactly that (2 zeta branches x 3 x transcripts = 6
   leaves), which is independent evidence the structure is 2-challenge.
   Classical tree forking costs about (leaves - 1)*log2(Q), so 5*log2(Q)
   instead of 2*log2(Q).

2. QROM LOSS COMPOUNDS PER ROUND. The measure-and-reprogram technique
   (Don-Fehr-Majenz-Schaffner) loses O(Q^2) per reprogrammed round; for
   mu rounds the published multi-round bounds are O(Q^{2mu}), i.e.
   2*mu*log2(Q). With mu = 2 that is 4*log2(Q), double what was charged.

At Q = 2^64 the correction is severe:

    charged before : 256 - 128 (forking, t=3) - 128 (QROM, 3-move) = ~0
    actual         : 256 - 320 (forking, 6-leaf tree) - 256 (QROM, mu=2)
                   = -320 bits

So the optimistic residual was not merely thin, it was computed for the
wrong protocol.

CAN THE ROUND BE REMOVED?
-------------------------
Yes, possibly -- and this is the actionable part. zeta only supplies the
aggregation weights zeta^i that batch S accounts into one check. Options:

  a) FIX zeta to a public constant (e.g. zeta = 1 or a fixed generator).
     Then it is not a challenge at all, mu drops to 1, and the protocol
     becomes 3-move. Cost: aggregation across accounts is no longer
     random, so a cheating prover may cancel errors between accounts. This
     needs a soundness argument PER ACCOUNT instead of amortised, which
     may be affordable at S <= 2 (the paper's own regime).
  b) DERIVE zeta from the statement ONLY, with commitments bound into the
     statement first, so the prover cannot grind it after commitment. This
     is nearly what the code does; the gap is that bit_commitments are
     hashed into zeta rather than fixed beforehand.
  c) Accept mu = 2 and pay 4*log2(Q).

`round_reduction_options()` records these with their costs. (a) and (b) are
real design changes needing a soundness argument; neither is done here.

HONEST SCOPE
------------
This module identifies the round structure from the code, computes the
resulting losses under published multi-round bounds, and corrects the
earlier figures. It does NOT prove Fiat-Shamir security, and the specific
multi-round QROM constant depends on which theorem is instantiated -- still
an open obligation. What is now established is that the loss exponent
depends on mu, and that mu = 2 here, not 1.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


class RoundStructureError(ValueError):
    """Raised on inconsistent round-structure parameters."""


@dataclass(frozen=True)
class RoundStructure:
    """The interactive shape underlying the Fiat-Shamir transform."""

    challenges: int
    branches_per_challenge: tuple
    description: str

    def __post_init__(self) -> None:
        if self.challenges < 1:
            raise RoundStructureError("a Sigma protocol has at least one challenge")
        if len(self.branches_per_challenge) != self.challenges:
            raise RoundStructureError(
                "branch count must be given for every challenge round"
            )
        if any(b < 2 for b in self.branches_per_challenge):
            raise RoundStructureError(
                "each challenge round needs at least 2 branches to extract"
            )

    @property
    def moves(self) -> int:
        """2*challenges + 1 moves in the interactive protocol."""
        return 2 * self.challenges + 1

    @property
    def extraction_leaves(self) -> int:
        """Total accepting transcripts a tree extractor needs."""
        total = 1
        for branches in self.branches_per_challenge:
            total *= branches
        return total

    def forking_loss_bits(self, queries: int) -> float:
        """(leaves - 1)*log2(Q) for classical tree forking."""
        if queries <= 0:
            raise RoundStructureError("query count must be positive")
        return (self.extraction_leaves - 1) * math.log2(queries)

    def qrom_loss_bits(self, queries: int) -> float:
        """2*mu*log2(Q): measure-and-reprogram loses O(Q^2) per round."""
        if queries <= 0:
            raise RoundStructureError("query count must be positive")
        return 2.0 * self.challenges * math.log2(queries)

    def total_loss_bits(self, queries: int) -> float:
        return self.forking_loss_bits(queries) + self.qrom_loss_bits(queries)


def chitin_round_structure() -> RoundStructure:
    """The structure actually implemented in binary_protocol1_ring.py.

    Two challenges: zeta (over the bit commitments) then x (over E, F, G).
    Branch counts match pqct/protocol1_family.py's extraction tree, which
    uses 2 zeta branches and 3 x transcripts per branch.
    """
    return RoundStructure(
        challenges=2,
        branches_per_challenge=(2, 3),
        description=(
            "P->V: B_i | V->P: zeta | P->V: E,F,G | V->P: x | P->V: g,z_g,z_b "
            "-- five moves, two challenges, extraction tree 2x3 = 6 leaves"
        ),
    )


def three_move_structure() -> RoundStructure:
    """The (incorrect) 3-move shape the earlier framework assumed."""
    return RoundStructure(
        challenges=1,
        branches_per_challenge=(3,),
        description="P->V: commit | V->P: x | P->V: respond -- three moves",
    )


@dataclass(frozen=True)
class LossComparison:
    """Earlier (3-move) figures against the corrected multi-round ones."""

    queries: int
    soundness_bits: float
    assumed: RoundStructure
    actual: RoundStructure

    @property
    def assumed_total(self) -> float:
        return self.assumed.total_loss_bits(self.queries)

    @property
    def actual_total(self) -> float:
        return self.actual.total_loss_bits(self.queries)

    @property
    def assumed_residual(self) -> float:
        return self.soundness_bits - self.assumed_total

    @property
    def actual_residual(self) -> float:
        return self.soundness_bits - self.actual_total

    @property
    def correction_bits(self) -> float:
        """How much worse the corrected analysis is."""
        return self.assumed_residual - self.actual_residual

    def summary(self) -> dict:
        return {
            "queries_log2": round(math.log2(self.queries), 1),
            "soundness_bits": round(self.soundness_bits, 1),
            "assumed_structure": {
                "moves": self.assumed.moves,
                "challenges": self.assumed.challenges,
                "extraction_leaves": self.assumed.extraction_leaves,
                "forking_bits": round(
                    self.assumed.forking_loss_bits(self.queries), 1),
                "qrom_bits": round(
                    self.assumed.qrom_loss_bits(self.queries), 1),
                "residual": round(self.assumed_residual, 1),
            },
            "actual_structure": {
                "moves": self.actual.moves,
                "challenges": self.actual.challenges,
                "extraction_leaves": self.actual.extraction_leaves,
                "forking_bits": round(
                    self.actual.forking_loss_bits(self.queries), 1),
                "qrom_bits": round(
                    self.actual.qrom_loss_bits(self.queries), 1),
                "residual": round(self.actual_residual, 1),
            },
            "correction_bits": round(self.correction_bits, 1),
            "verdict": (
                "the earlier residual was computed for a THREE-MOVE protocol; "
                "the implemented protocol has two Fiat-Shamir challenges, so "
                f"the true optimistic residual is {self.actual_residual:.0f} "
                f"bits, {self.correction_bits:.0f} bits worse than reported"
            ),
        }


def compare_losses(queries: int = 2 ** 64,
                   soundness_bits: float = 256.04) -> LossComparison:
    return LossComparison(
        queries=queries,
        soundness_bits=soundness_bits,
        assumed=three_move_structure(),
        actual=chitin_round_structure(),
    )


def round_reduction_options() -> tuple:
    """Ways to get back to mu = 1, with honest costs."""
    return (
        {
            "option": "fix zeta to a public constant",
            "effect": "mu = 1, protocol becomes 3-move",
            "saving_bits_at_2_64": 2.0 * 64.0 + 3.0 * 64.0,
            "cost": (
                "aggregation across accounts is no longer randomised, so a "
                "cheating prover may cancel errors between accounts; needs a "
                "PER-ACCOUNT soundness argument instead of an amortised one. "
                "Plausibly affordable at S <= 2 (the paper's own regime)."
            ),
            "status": "NOT ATTEMPTED -- needs a soundness argument",
        },
        {
            "option": "bind commitments into the statement before deriving zeta",
            "effect": (
                "zeta becomes non-adaptive (prover cannot grind it after "
                "committing), so it may not need a Fiat-Shamir round at all"
            ),
            "saving_bits_at_2_64": 2.0 * 64.0 + 3.0 * 64.0,
            "cost": (
                "requires the commitments to be fixed by the transaction "
                "envelope BEFORE proof generation. pqct/tx_envelope.py "
                "already binds a statement, so this is close -- the gap is "
                "that bit_commitments are currently hashed INTO zeta rather "
                "than fixed beforehand."
            ),
            "status": "NOT ATTEMPTED -- closest to tractable",
        },
        {
            "option": "accept mu = 2",
            "effect": "pay 4*log2(Q) QROM and 5*log2(Q) forking",
            "saving_bits_at_2_64": 0.0,
            "cost": "residual is -320 bits at Q = 2^64; not viable as-is",
            "status": "current state",
        },
    )


__all__ = [
    "LossComparison",
    "RoundStructure",
    "RoundStructureError",
    "chitin_round_structure",
    "compare_losses",
    "round_reduction_options",
    "three_move_structure",
]
