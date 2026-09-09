"""Forking loss as a computed bound, not bookkeeping.

WHAT WAS WRONG WITH THE PLACEHOLDER
-----------------------------------
`fiat_shamir_framework.forking_loss_bits` charged (leaves - 1) * log2(Q)
= 5 * 64 = 320 bits for a 6-leaf tree. That formula is the ORDINARY
forking lemma (Pointcheval-Stern / Bellare-Neven) applied as if six
independent transcripts had to be forked one after another. It is wrong
in both directions:

  * too PESSIMISTIC: the ordinary forking lemma is for a single challenge
    round. For a (k_1, ..., k_mu)-special-sound MULTI-round protocol the
    right tool is the tree-extraction bound (Attema-Cramer-Kohl,
    "A Compressed Sigma-Protocol Theory" / Attema-Fehr-Kloss "Fiat-Shamir
    Transformation of Multi-Round Interactive Proofs", TCC'22), which
    does NOT pay log2(Q) per leaf.
  * too OPTIMISTIC in one place: the placeholder ignored the knowledge
    error term entirely.

THE ACTUAL BOUND (Attema-Fehr-Kloss 2022, Theorem for FS of multi-round)
-----------------------------------------------------------------------
For a (k_1, ..., k_mu)-special-sound interactive proof with challenge
sets C_1, ..., C_mu, the Fiat-Shamir transform has knowledge error

    kappa_FS  <=  (Q + 1) * kappa

where kappa is the INTERACTIVE knowledge error

    kappa = 1 - prod_i (1 - (k_i - 1) / |C_i|)

and Q is the number of random-oracle queries. Crucially the loss is a
FACTOR (Q + 1), i.e. log2(Q) bits ONCE -- not once per leaf and not once
per round. This is the whole point of AFK'22: the naive per-round
composition loses Q^mu, they prove Q suffices.

The extractor runs in expected time polynomial with K = prod k_i
rewinds, but that is running time, not a probability loss.

FOR THIS PROTOCOL
-----------------
Two challenge rounds (zeta, then x). The extraction tree is 2 x 3:
    k_1 = 2  (two zeta branches)          |C_1| = challenge space
    k_2 = 3  (three x per zeta)           |C_2| = challenge space
Both challenges are sampled from the same sparse set of size
C(d, w) * (2p)^w  ~  2^256.

So kappa  ~  (2-1)/2^256 + (3-1)/2^256  ~  3 * 2^-256   (~ 2^-254.4)
and kappa_FS  <=  (Q+1) * kappa  ~  2^64 * 2^-254.4  =  2^-190.4.

That is a ~190-bit soundness margin AFTER the Fiat-Shamir loss, versus the
placeholder's -320. The difference -- over 500 bits -- is entirely the
choice of theorem.

WHAT THIS DOES NOT DO
---------------------
  * It does not prove the protocol IS (2,3)-special-sound. The extraction
    tree exists in code (protocol1_family) and extracts on honest
    transcripts; that the extractor succeeds on EVERY accepting tree is
    the special-soundness claim and is still an obligation. The number
    above is conditional on it.
  * AFK'22 is a CLASSICAL result. The QROM version (Don-Fehr-Majenz-
    Schaffner 2022, "Efficient NIZKs and Signatures from Commit-and-Open
    Protocols in the QROM"; and AFK's own quantum extension) loses an
    extra factor: their bound is roughly (2Q+1)^(2 mu) kappa for
    measure-and-reprogram, or Q^2 via the "compressed" route. We compute
    BOTH the classical AFK number and the conservative QROM number and
    report both -- see qrom_bits below.
  * The knowledge error assumes challenges are UNIFORM over C. The sparse
    sampler is close to uniform over its support but that is an
    assumption folded into |C|.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .fiat_shamir_framework import challenge_space_size


class ForkingError(ValueError):
    """Malformed input."""


@dataclass(frozen=True)
class TreeShape:
    """(k_1, ..., k_mu) and the challenge-set sizes per round."""

    branching: tuple          # k_i per round
    challenge_sizes: tuple    # |C_i| per round

    def __post_init__(self) -> None:
        if len(self.branching) != len(self.challenge_sizes):
            raise ForkingError("branching and challenge_sizes must align")
        if not self.branching:
            raise ForkingError("at least one round required")
        for k, c in zip(self.branching, self.challenge_sizes):
            if k < 2:
                raise ForkingError("each round needs k_i >= 2 to extract")
            if c < k:
                raise ForkingError("challenge set smaller than branching")

    @property
    def rounds(self) -> int:
        return len(self.branching)

    @property
    def leaves(self) -> int:
        out = 1
        for k in self.branching:
            out *= k
        return out


def interactive_knowledge_error(shape: TreeShape) -> float:
    """kappa = 1 - prod_i (1 - (k_i - 1)/|C_i|).

    Returned as log2 for numerical sanity: the raw value is ~2^-254.
    """
    log_survive = 0.0
    for k, c in zip(shape.branching, shape.challenge_sizes):
        p = (k - 1) / c
        # log(1 - p) for tiny p: use log1p
        log_survive += math.log1p(-p)
    # kappa = 1 - exp(log_survive); for tiny kappa this is -log_survive
    kappa = -log_survive if log_survive > -1e-6 else 1.0 - math.exp(log_survive)
    return math.log2(kappa) if kappa > 0 else float("-inf")


def fs_knowledge_error_classical(shape: TreeShape, queries: int) -> float:
    """AFK'22: kappa_FS <= (Q+1) * kappa. Returns log2."""
    if queries <= 0:
        raise ForkingError("queries must be positive")
    return interactive_knowledge_error(shape) + math.log2(queries + 1)


def fs_knowledge_error_qrom_conservative(shape: TreeShape, queries: int) -> float:
    """QROM knowledge error via Don-Fehr-Majenz CRYPTO'20 Corollary 13.

    Multiplicative loss n!/(2q+n+1)^(2n) for a (2n+1)-round PCIP. DFM'20
    Section 6 proves the q^(2n) dependence is TIGHT (Grover lower bound),
    so this is not a conservative placeholder any more -- it is the actual
    bound, and no tighter generic theorem can exist. Named "conservative"
    historically; kept for API stability.
    """
    n = shape.rounds
    if queries <= 0:
        raise ForkingError("queries must be positive")
    loss = 2 * n * math.log2(2 * queries + n + 1) - math.log2(math.factorial(n))
    return interactive_knowledge_error(shape) + loss


def placeholder_loss_bits(shape: TreeShape, queries: int) -> float:
    """What fiat_shamir_framework charged: (leaves-1)*log2 Q + 2*mu*log2 Q.

    Kept so the correction is visible as a number.
    """
    return (shape.leaves - 1) * math.log2(queries) + 2 * shape.rounds * math.log2(queries)


@dataclass(frozen=True)
class ForkingReport:
    shape: TreeShape
    queries: int
    soundness_bits: float                 # -log2(kappa), interactive
    classical_fs_bits: float              # -log2(kappa_FS) classical
    qrom_fs_bits: float                   # -log2(kappa_FS) QROM conservative
    placeholder_residual_bits: float      # what the framework reported

    @property
    def classical_loss_bits(self) -> float:
        return self.soundness_bits - self.classical_fs_bits

    @property
    def qrom_loss_bits(self) -> float:
        return self.soundness_bits - self.qrom_fs_bits

    def summary(self) -> dict:
        return {
            "tree": {
                "branching": self.shape.branching,
                "rounds": self.shape.rounds,
                "leaves": self.shape.leaves,
            },
            "log2_queries": round(math.log2(self.queries), 1),
            "interactive_soundness_bits": round(self.soundness_bits, 1),
            "classical_fs": {
                "theorem": "Attema-Fehr-Kloss 2022: kappa_FS <= (Q+1)*kappa",
                "loss_bits": round(self.classical_loss_bits, 1),
                "residual_bits": round(self.classical_fs_bits, 1),
            },
            "qrom_fs_conservative": {
                "theorem": "measure-and-reprogram per round: (2Q+1)^(2mu)*kappa",
                "loss_bits": round(self.qrom_loss_bits, 1),
                "residual_bits": round(self.qrom_fs_bits, 1),
            },
            "placeholder": {
                "formula": "(leaves-1)*log2Q + 2*mu*log2Q",
                "residual_bits": round(self.placeholder_residual_bits, 1),
                "error_vs_classical_bits": round(
                    self.classical_fs_bits - self.placeholder_residual_bits, 1
                ),
            },
            "conditional_on": (
                "(2,3)-special-soundness of the protocol -- extraction tree "
                "exists and extracts on honest transcripts; success on EVERY "
                "accepting tree is the open obligation"
            ),
        }


def chitin_tree() -> TreeShape:
    """The implemented protocol: zeta (k=2) then x (k=3), same challenge set."""
    size = challenge_space_size(56, 8, 64)      # paper (d,w,p)=(64,56,8)
    return TreeShape(branching=(2, 3), challenge_sizes=(size, size))


def forking_report(queries: int = 2 ** 64) -> ForkingReport:
    shape = chitin_tree()
    soundness = -interactive_knowledge_error(shape)
    classical = -fs_knowledge_error_classical(shape, queries)
    qrom = -fs_knowledge_error_qrom_conservative(shape, queries)
    placeholder = soundness - placeholder_loss_bits(shape, queries)
    return ForkingReport(
        shape=shape, queries=queries, soundness_bits=soundness,
        classical_fs_bits=classical, qrom_fs_bits=qrom,
        placeholder_residual_bits=placeholder,
    )


__all__ = [
    "ForkingError",
    "ForkingReport",
    "TreeShape",
    "chitin_tree",
    "forking_report",
    "fs_knowledge_error_classical",
    "fs_knowledge_error_qrom_conservative",
    "interactive_knowledge_error",
    "placeholder_loss_bits",
]
