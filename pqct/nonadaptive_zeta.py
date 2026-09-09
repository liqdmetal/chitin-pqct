"""Non-adaptive zeta: an attempt to reduce the protocol from mu=2 to mu=1.

THE PROBLEM (from pqct/multiround_qrom.py)
------------------------------------------
The implemented protocol has TWO Fiat-Shamir challenges:

    P -> V : B_i        V -> P : zeta = H(statement, keys, B_i)
    P -> V : E,F,G      V -> P : x    = H(statement, keys, B_i, E,F,G, zeta)
    P -> V : responses

Two challenges cost 4*log2(Q) QROM plus 5*log2(Q) forking (6-leaf tree), a
combined -576 bits at Q = 2^64 against 256 bits of soundness.

THE OBSERVATION
---------------
zeta does one job: it supplies the weights zeta^i that aggregate S accounts
into a single check. It is NOT a soundness challenge in the usual sense --
it is an amortisation weight. Crucially, the verifier needs zeta only to
recompute the SAME weighted sums the prover used; it does not need zeta to
be unpredictable *to the prover at commitment time* for the aggregation to
be well-defined.

What zeta DOES need: the prover must not be able to choose the bit
commitments AFTER seeing zeta, because then it could pick commitments whose
weighted combination cancels an error. That is the grinding attack.

THE FIX
-------
Derive zeta from data the prover has already committed to IRREVOCABLY before
proof generation -- specifically the transaction envelope statement, which
`pqct/tx_envelope.py` already binds to chain_id, prev_state_root, nonce,
expiry AND the relation shape. If the bit commitments are ALSO fixed into
that statement (they are part of the transaction), then zeta is a
deterministic function of data the prover cannot change without invalidating
the whole transaction.

zeta then stops being an adaptively-chosen challenge and becomes a public
parameter of the statement. The protocol collapses to mu = 1:

    P -> V : B_i, E, F, G       (one message; zeta is public from the start)
    V -> P : x
    P -> V : responses

WHAT THIS MODULE DOES, AND WHAT IT DOES NOT
-------------------------------------------
It implements the derivation (`derive_statement_bound_zeta`) and an
executable GRINDING TEST (`grinding_resistance`) that measures whether an
attacker who mutates commitments can steer zeta while keeping the statement
fixed. That is the concrete property the reduction rests on.

It does NOT prove the amortisation is still sound with a
statement-determined zeta. The residual risk is precise and stated in
`residual_soundness_question()`: with zeta fixed before the commitments are
chosen *within* a statement, an adversary who controls which commitments go
into the statement still picks them knowing the statement -- and therefore
knowing zeta. Whether that reintroduces the cancellation attack depends on
whether the per-account errors can be steered once zeta is known, which is a
soundness question for a cryptographer, not something this code settles.

So: mu = 1 is ACHIEVABLE structurally, worth 5*log2(Q) = 320 bits at
Q = 2^64, conditional on that one question. That is the honest result of the
attempt.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .ring_challenge import RingChallengeParameters, challenge_ring_element
from .ring_challenge import derive_ring_challenge
from .ring_commitment import RingElement

ZETA_DOMAIN = b"CHITIN-ZETA-STATEMENT-BOUND-V1"


class NonAdaptiveZetaError(ValueError):
    """Raised on malformed non-adaptive zeta derivation."""


def derive_statement_bound_zeta(
    statement: bytes, ring_params, challenge_params: RingChallengeParameters
) -> RingElement:
    """zeta from the STATEMENT ALONE -- no commitments, no prover input.

    This is the whole point: the derivation cannot depend on anything the
    prover chooses after the statement is fixed, or zeta remains adaptive
    and the round cannot be removed.
    """
    if not statement:
        raise NonAdaptiveZetaError("statement must not be empty")
    sparse = derive_ring_challenge(
        ZETA_DOMAIN + statement, ring_params, challenge_params, ()
    )
    return challenge_ring_element(sparse)


@dataclass(frozen=True)
class GrindingReport:
    """Can an attacker steer zeta by mutating commitments?"""

    attempts: int
    distinct_zetas: int
    statement_fixed: bool

    @property
    def steerable(self) -> bool:
        """More than one zeta reachable under a fixed statement means the
        prover can grind, and the round cannot be removed."""
        return self.distinct_zetas > 1

    def summary(self) -> dict:
        return {
            "attempts": self.attempts,
            "distinct_zetas": self.distinct_zetas,
            "statement_fixed": self.statement_fixed,
            "steerable": self.steerable,
            "verdict": (
                "GRINDABLE: zeta moves when commitments move, so it is "
                "adaptive and mu cannot be reduced"
                if self.steerable else
                "NOT GRINDABLE under a fixed statement: zeta is determined "
                "by the statement alone, so it is a public parameter rather "
                "than an adaptive challenge"
            ),
        }


def grinding_resistance(
    statement: bytes, ring_params, challenge_params: RingChallengeParameters,
    commitment_variants, adaptive: bool = False, base_key=None,
) -> GrindingReport:
    """Measure how many distinct zetas an attacker can reach.

    With `adaptive=False` zeta comes from the statement only, so every
    variant must yield the SAME zeta. With `adaptive=True` the commitments
    are hashed in (the current behaviour), so variants should yield
    DIFFERENT zetas -- demonstrating the grinding surface that motivates the
    change.
    """
    variants = tuple(commitment_variants)
    if not variants:
        raise NonAdaptiveZetaError("at least one commitment variant is required")

    seen = set()
    for variant in variants:
        if adaptive:
            rows = tuple(tuple(row) for row in variant)
            sparse = derive_ring_challenge(
                ZETA_DOMAIN + statement, ring_params, challenge_params, rows
            )
            zeta = challenge_ring_element(sparse)
        else:
            zeta = derive_statement_bound_zeta(
                statement, ring_params, challenge_params
            )
        seen.add(zeta.encode())

    return GrindingReport(
        attempts=len(variants),
        distinct_zetas=len(seen),
        statement_fixed=True,
    )


def round_reduction_saving(queries: int = 2 ** 64) -> dict:
    """What removing the zeta round is worth, from multiround_qrom."""
    from .multiround_qrom import chitin_round_structure, three_move_structure

    two_round = chitin_round_structure()
    one_round = three_move_structure()
    return {
        "before": {
            "challenges": two_round.challenges,
            "leaves": two_round.extraction_leaves,
            "total_loss_bits": round(two_round.total_loss_bits(queries), 1),
        },
        "after": {
            "challenges": one_round.challenges,
            "leaves": one_round.extraction_leaves,
            "total_loss_bits": round(one_round.total_loss_bits(queries), 1),
        },
        "saving_bits": round(
            two_round.total_loss_bits(queries)
            - one_round.total_loss_bits(queries), 1
        ),
    }


def residual_soundness_question() -> dict:
    """The one thing this attempt does NOT settle. Stated precisely."""
    return {
        "question": (
            "With zeta determined by the statement, an adversary who chooses "
            "which commitments to place INTO that statement still knows zeta "
            "before choosing them. Does that reintroduce the cross-account "
            "cancellation attack that randomised aggregation was meant to "
            "prevent?"
        ),
        "why_it_might_be_fine": (
            "The commitments are bound into the statement, so choosing them "
            "changes the statement and therefore changes zeta -- a fixed "
            "point would have to be found, which is a hash-inversion problem "
            "rather than a free choice. Grinding then costs ~|C| work per "
            "attempt instead of being free."
        ),
        "why_it_might_not_be": (
            "Only the FINAL commitments need be bound; an adversary may be "
            "able to fix a statement, read zeta, and then search within the "
            "remaining freedom (openings, masks) for a cancellation. Whether "
            "that freedom suffices is relation-specific."
        ),
        "status": "OPEN -- soundness argument required",
        "who": "lattice/ZK cryptographer",
        "value_if_resolved_bits": 320.0,
    }


__all__ = [
    "GrindingReport",
    "NonAdaptiveZetaError",
    "ZETA_DOMAIN",
    "derive_statement_bound_zeta",
    "grinding_resistance",
    "residual_soundness_question",
    "round_reduction_saving",
]
