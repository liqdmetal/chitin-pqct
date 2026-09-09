"""The QROM bound, settled by the actual theorem -- and the answer is "no".

WHAT I HOPED
------------
That Attema-Fehr-Kloss's quantum extension, or some tighter QROM result,
would shrink the 196-bit QROM penalty and flip the budget to a positive
residual. This module records the attempt and its outcome honestly.

THE ACTUAL THEOREM (Don-Fehr-Majenz, CRYPTO 2020, arXiv:2003.05207v3)
--------------------------------------------------------------------
"The Measure-and-Reprogram Technique 2.0: Multi-Round Fiat-Shamir and
More". Corollary 13 (their numbering), verbatim structure:

    Pr[ S^A convinces the INTERACTIVE verifier ]
        >=  n! / (2q + n + 1)^(2n)  *  Pr[ A breaks FS[Pi] ]  -  eps

for a (2n+1)-round PCIP, q quantum RO queries, additive eps summing to
n!/|C| over instances.

So the multiplicative QROM loss for n=2 rounds is

    (2q + 3)^4 / 2!   ->   log2 = 4*log2(2q+3) - 1  ~  260 - 1 = 259 bits

at q = 2^64. My conservative placeholder charged (2q+1)^(2n) = 260 bits.
The real theorem is ONE BIT better. That is the whole improvement.

WHY THERE IS NO ESCAPE (Section 1 and the lower bound, their Section 6)
------------------------------------------------------------------------
DFM'20 prove a Grover-based LOWER BOUND: the O(q^2) loss for Sigma-
protocols is tight up to a factor 4, and "this extends to our new
multi-round result, proving it tight up to a factor that depends on the
number of rounds only". The q^(2n) loss for generic multi-round FS in the
QROM is UNAVOIDABLE. No tighter generic theorem exists to cite, because
one cannot exist.

The classical bound (AFK'22, (Q+1)*kappa) and the quantum bound
(DFM'20, ~q^(2n)*kappa) are therefore both correct and both tight in
their respective models. The 196-bit gap between them is the genuine
price of the QROM for a 2-round protocol, not slack in my bookkeeping.

WHAT WOULD ACTUALLY CHANGE THE NUMBER
-------------------------------------
Only two things, both structural, neither a better citation:

  1. REDUCE TO ONE ROUND (n=1). Then the loss is (2q+3)^2 / 1! -> 130
     bits, and the residual becomes 254.5 - 130 = +124 bits. This is
     exactly what the non-adaptive-zeta work (nonadaptive_zeta.py,
     zeta_cancellation.py, cancellation_bound.py, zeta_grinding.py, the
     BKZ-40 reduction) has been building toward. Every one of those
     modules is now load-bearing for the QROM budget, not just the
     classical one. Status: cancellation and grinding both narrowed to
     computed answers; special-soundness of the 1-round variant is the
     remaining obligation.

  2. ABANDON GENERIC FS for a protocol-specific QROM proof (e.g. the
     collapsing route: DFM'20 Theorem 28 / Corollary 29 give a quantum
     PROOF OF KNOWLEDGE via unique-responses/collapsingness, with a
     polynomial loss eps^7 in the interactive setting -- but that is for
     the interactive protocol's PoK property, and it still passes through
     Corollary 13 for the FS transform). No escape from q^(2n) here
     either; collapsingness buys the PoK property, not a smaller FS loss.

THE HONEST BUDGET CONSEQUENCE
-----------------------------
The budget's QROM line moves from "unestablished, 196 bits" to
"ESTABLISHED (DFM'20 Cor. 13, tight), 195 bits". Its status improves --
it is now an applied theorem, not a placeholder -- but the NUMBER barely
moves. The residual stays negative at ~-3 bits under the pessimistic
quantum model, and that is the true state of affairs for a 2-round FS
protocol at Q=2^64.

The route to a positive QROM residual is the 1-round reduction, worth
~130 bits. That is the highest-value item and it is a soundness question
about zeta, which is exactly where the last five modules have been
working. This module makes that dependency explicit.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .forking_bound import chitin_tree, interactive_knowledge_error


class QROMError(ValueError):
    """Bad input."""


def dfm20_multiround_loss_bits(queries: int, rounds: int) -> float:
    """log2 of the multiplicative loss in DFM'20 Corollary 13:
        (2q + n + 1)^(2n) / n!
    """
    if queries <= 0 or rounds < 1:
        raise QROMError("queries must be positive and rounds >= 1")
    n = rounds
    return 2 * n * math.log2(2 * queries + n + 1) - math.log2(math.factorial(n))


def placeholder_loss_bits(queries: int, rounds: int) -> float:
    """What forking_bound charged: (2q+1)^(2n), no n! credit."""
    return 2 * rounds * math.log2(2 * queries + 1)


def dfm20_additive_error_bits(challenge_size: int, rounds: int) -> float:
    """log2 of the additive term n!/|C| (summed over instances)."""
    return math.log2(math.factorial(rounds)) - math.log2(challenge_size)


@dataclass(frozen=True)
class QROMReport:
    queries: int
    rounds: int
    interactive_soundness_bits: float
    dfm20_loss_bits: float
    placeholder_loss_bits: float
    additive_error_bits: float

    @property
    def residual_bits(self) -> float:
        return self.interactive_soundness_bits - self.dfm20_loss_bits

    @property
    def improvement_over_placeholder_bits(self) -> float:
        return self.placeholder_loss_bits - self.dfm20_loss_bits

    def summary(self) -> dict:
        return {
            "theorem": "Don-Fehr-Majenz CRYPTO'20 Cor.13: n!/(2q+n+1)^(2n), TIGHT (their Sec.6 lower bound)",
            "rounds": self.rounds,
            "log2_queries": round(math.log2(self.queries), 1),
            "interactive_soundness_bits": round(self.interactive_soundness_bits, 1),
            "qrom_loss_bits": round(self.dfm20_loss_bits, 1),
            "placeholder_loss_bits": round(self.placeholder_loss_bits, 1),
            "improvement_over_placeholder_bits": round(self.improvement_over_placeholder_bits, 2),
            "residual_bits": round(self.residual_bits, 1),
            "additive_error_log2": round(self.additive_error_bits, 1),
            "established": True,
            "tight": True,
        }


def qrom_report(queries: int = 2 ** 64, rounds: int | None = None) -> QROMReport:
    shape = chitin_tree()
    n = shape.rounds if rounds is None else rounds
    soundness = -interactive_knowledge_error(shape)
    return QROMReport(
        queries=queries,
        rounds=n,
        interactive_soundness_bits=soundness,
        dfm20_loss_bits=dfm20_multiround_loss_bits(queries, n),
        placeholder_loss_bits=placeholder_loss_bits(queries, n),
        additive_error_bits=dfm20_additive_error_bits(shape.challenge_sizes[0], n),
    )


def one_round_alternative(queries: int = 2 ** 64) -> dict:
    """What the residual becomes if zeta is made non-adaptive (n=1).

    The interactive soundness for a 1-round (3-special-sound in x) variant
    is (3-1)/|C| = 2/|C|, slightly better than the 2-round 3/|C|.
    """
    shape = chitin_tree()
    size = shape.challenge_sizes[0]
    soundness_1round = math.log2(size) - 1.0          # -log2(2/|C|)
    loss = dfm20_multiround_loss_bits(queries, 1)
    two = qrom_report(queries)
    return {
        "one_round_soundness_bits": round(soundness_1round, 1),
        "one_round_qrom_loss_bits": round(loss, 1),
        "one_round_residual_bits": round(soundness_1round - loss, 1),
        "two_round_residual_bits": round(two.residual_bits, 1),
        "gain_bits": round((soundness_1round - loss) - two.residual_bits, 1),
        "dependency": (
            "requires non-adaptive zeta to be SOUND: cancellation "
            "(cancellation_bound + BKZ-40: shortest = p, closed) and "
            "grinding (zeta_grinding: peak-grinding impossible, closed); "
            "3-special-soundness of the resulting 1-round protocol is the "
            "remaining obligation"
        ),
    }


__all__ = [
    "QROMError",
    "QROMReport",
    "dfm20_additive_error_bits",
    "dfm20_multiround_loss_bits",
    "one_round_alternative",
    "placeholder_loss_bits",
    "qrom_report",
]
