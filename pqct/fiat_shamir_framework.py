"""Framework for the Fiat-Shamir / QROM security argument.

WHAT THIS IS
------------
NOT a proof. A proof of Fiat-Shamir security for this construction in the
quantum random-oracle model is research-paper-scale work and is not
attempted here or anywhere else in this repository.

What this module IS: the argument's SKELETON made executable and checkable.
It states each obligation the proof must discharge, records which ones the
codebase can currently evidence, computes the concrete quantities the proof
would be parameterised by (soundness error, challenge-space size, rewinding
loss, QROM reprogramming loss), and refuses to report a security level while
any obligation is unmet.

The value is in making the gap precise and non-negotiable: right now the
soundness error and the QROM loss can be COMPUTED, while the extractor's
existence and the reprogramming argument CANNOT be discharged by code. A
framework that quietly conflated those two categories would be worse than
none, so `overall_status` is OPEN whenever a proof-obligation is open.

WHY THE INTERACTIVE WORK IS NOT ENOUGH
--------------------------------------
The repository has a real 3-transcript extractor
(`pqct/three_transcript_extraction.py`) that recovers a relaxed witness and
detects non-affine responses. That establishes SPECIAL SOUNDNESS in a
bounded, executable sense: GIVEN three accepting transcripts on distinct
challenges, a witness comes out. Fiat-Shamir needs strictly more:

  1. From a single non-interactive prover, PRODUCE those three transcripts.
     Classically this is rewinding (forking lemma). Quantumly, rewinding a
     superposition query is not generally possible -- measuring collapses
     the state -- so the classical argument does not transfer.
  2. Handle the adversary's Q queries to the random oracle, each of which
     may be a SUPERPOSITION over inputs.
  3. Reprogram the oracle at the challenge point without the adversary
     detecting it, paying the QROM reprogramming loss.

Each is a named obligation below.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum


class FrameworkError(ValueError):
    """Raised on inconsistent framework parameters."""


class Status(Enum):
    """Whether an obligation is discharged, and by what kind of evidence."""

    CODE_EVIDENCED = "code-evidenced"       # executable check in this repo
    COMPUTED = "computed"                   # a number this module derives
    OPEN = "open"                           # needs a human cryptographer
    NOT_ATTEMPTED = "not-attempted"         # out of scope here


@dataclass(frozen=True)
class Obligation:
    """One thing the Fiat-Shamir proof must establish."""

    name: str
    requirement: str
    status: Status
    evidence: str

    @property
    def discharged(self) -> bool:
        return self.status in (Status.CODE_EVIDENCED, Status.COMPUTED)


def challenge_space_size(weight: int, coefficient_bound: int, degree: int) -> int:
    """|C_{w,p}| for the sparse challenge set: choose w of d positions, each
    coefficient one of 2p nonzero values (+-1..+-p).

    This is the soundness denominator: a cheating prover who guesses the
    challenge wins, so 1/|C| is the floor on soundness error per repetition.
    """
    if min(weight, coefficient_bound, degree) <= 0:
        raise FrameworkError("weight, bound and degree must be positive")
    if weight > degree:
        raise FrameworkError("weight cannot exceed the ring degree")
    return math.comb(degree, weight) * (2 * coefficient_bound) ** weight


def soundness_error_bits(weight: int, coefficient_bound: int,
                         degree: int) -> float:
    """log2(1/|C|): bits of soundness from one challenge draw."""
    size = challenge_space_size(weight, coefficient_bound, degree)
    return math.log2(size)


def forking_loss_bits(queries: int, transcripts: int = 3) -> float:
    """Classical forking-lemma loss.

    CORRECTED: `transcripts` must be the number of TREE LEAVES, not the
    number of challenges per round. The implemented protocol has TWO
    Fiat-Shamir challenges (zeta then x), so extraction needs a 2x3 = 6-leaf
    tree, not 3 transcripts -- see pqct/multiround_qrom.py, which reads the
    structure off the derivation functions.

    Extracting `transcripts` accepting transcripts from a prover that
    succeeds with probability eps costs roughly eps^transcripts / Q^(t-1),
    i.e. a loss of about (transcripts-1)*log2(Q) bits plus the eps powers.
    """
    if queries <= 0:
        raise FrameworkError("query count must be positive")
    if transcripts < 2:
        raise FrameworkError("at least two transcripts are needed to extract")
    return (transcripts - 1) * math.log2(queries)


def qrom_reprogramming_loss_bits(queries: int, rounds: int = 1) -> float:
    """QROM adaptive-reprogramming loss: 2*rounds*log2(Q).

    CORRECTED: the loss COMPOUNDS PER REPROGRAMMED ROUND. The
    measure-and-reprogram technique (Don-Fehr-Majenz-Schaffner) loses
    O(Q^2) per round, so a mu-round protocol loses O(Q^{2mu}). Charging
    2*log2(Q) is only right for a single-challenge (three-move) protocol,
    and this one has mu = 2.

    Which precise theorem applies remains an open obligation; this is
    conservative bookkeeping with the correct round dependence.
    """
    if queries <= 0:
        raise FrameworkError("query count must be positive")
    if rounds < 1:
        raise FrameworkError("round count must be at least one")
    return 2.0 * rounds * math.log2(queries)


OBLIGATIONS = (
    Obligation(
        name="special-soundness-3-transcripts",
        requirement=(
            "Given three accepting transcripts on distinct challenges with a "
            "common first message, output a (relaxed) witness."
        ),
        status=Status.CODE_EVIDENCED,
        evidence=(
            "pqct/three_transcript_extraction.py: extracts relaxed bit y*b "
            "and mask -y*t, enforces cross-consistency "
            "(x1-x2)(g0-g1)==(x0-x1)(g1-g2) and the binary check B*(y-B)==0; "
            "17 tests including a non-affine attack caught only by the "
            "three-point identity. Refuses repeated challenges (y=0 would "
            "make every check vacuous)."
        ),
    ),
    Obligation(
        name="challenge-space-size",
        requirement=(
            "The challenge set must be large enough that guessing is "
            "negligible; 1/|C| bounds the per-repetition soundness error."
        ),
        status=Status.COMPUTED,
        evidence="challenge_space_size(); paper's C_{w,p} with w=56, p=8, d=64.",
    ),
    Obligation(
        name="commitment-binding-under-relaxation",
        requirement=(
            "The extracted opening is RELAXED (scaled by y = x_i - x_j). The "
            "binding argument must hold for relaxed openings, i.e. the "
            "M-SIS bound must cover y*witness, not just witness."
        ),
        status=Status.OPEN,
        evidence=(
            "pqct/hmc_binding_reduction.py does collision->M-SIS and the "
            "Eq.(2) check, and pqct/msis_hardness.py analyses the delta "
            "criterion. What is NOT established: that the relaxation factor "
            "y is benign, i.e. that a relaxed opening of y*b still implies a "
            "meaningful statement about b. Needs a cryptographer."
        ),
    ),
    Obligation(
        name="classical-rewinding-to-3-transcripts",
        requirement=(
            "From ONE non-interactive prover, obtain three accepting "
            "transcripts sharing a first message (forking lemma)."
        ),
        status=Status.CODE_EVIDENCED,
        evidence=(
            "Attema-Fehr-Kloss 2022 IS the multi-round forking lemma: "
            "kappa_FS <= (Q+1)*kappa, computed in pqct/forking_bound "
            "(64 bits at Q=2^64). It takes special-soundness as INPUT, and "
            "that is machine-checked in pqct/special_soundness: five "
            "adversaries (honest, non-affine, non-bit b=2, spliced witness, "
            "repeated challenge), zero counterexamples -- every accepting "
            "triple yields a relaxed witness or is refused. The non-bit case "
            "is decisive: it FOOLS the extractor's cross-consistency but the "
            "verifier's equation (B) rejects it, which is Step 3 of the "
            "argument working as designed. Still toy-parameter, enumerated "
            "adversaries, honest-key model."
        ),
    ),
    Obligation(
        name="quantum-rewinding-obstruction",
        requirement=(
            "Address why classical rewinding fails quantumly: measuring a "
            "superposition query collapses the adversary's state, so the "
            "forking lemma does not transfer."
        ),
        status=Status.NOT_ATTEMPTED,
        evidence=(
            "Requires a measure-and-reprogram or adaptive-reprogramming "
            "argument (Don-Fehr-Majenz-Schaffner 2019/2022; "
            "Grilo-Hovelmanns-Hulsing-Majenz 2021) instantiated for THIS "
            "protocol's round structure. Research-paper scale."
        ),
    ),
    Obligation(
        name="qrom-reprogramming-loss",
        requirement=(
            "Quantify the security loss from reprogramming the oracle at the "
            "challenge point against an adversary making Q quantum queries."
        ),
        status=Status.COMPUTED,
        evidence=(
            "qrom_reprogramming_loss_bits() = 2*log2(Q) as conservative "
            "bookkeeping. WHICH theorem applies is part of the "
            "quantum-rewinding obligation above, so this number is a budget "
            "line, not a derived bound."
        ),
    ),
    Obligation(
        name="transcript-simulation-shvzk",
        requirement=(
            "A simulator must produce transcripts indistinguishable from "
            "honest ones without the witness, including the abort behaviour."
        ),
        status=Status.OPEN,
        evidence=(
            "pqct/simulator_rejection.py implements the Lemma 6 "
            "witness-independent abort at rate 1/mu(phi), verified against "
            "the honest prover's measured rate (phi=15: target 0.965069, "
            "measured 0.966500), and pqct/truncation_distance.py bounds the "
            "finite-support gap exactly. What is NOT established: that the "
            "full transcript distributions are statistically close."
        ),
    ),
    Obligation(
        name="statement-binding",
        requirement=(
            "The hashed statement must bind everything the proof is about, "
            "so a proof cannot be transplanted to another context."
        ),
        status=Status.CODE_EVIDENCED,
        evidence=(
            "pqct/tx_envelope.py folds chain_id, prev_state_root, nonce, "
            "expiry and the relation shape into the Fiat-Shamir statement; "
            "4 subtests confirm mutating ANY field invalidates the proof. "
            "Challenge derivation is domain-separated and FS enforcement is "
            "the verifier default (pqct/binary_protocol1_ring.py, "
            "pqct/protocol5.py) after a real challenge-injection forgery."
        ),
    ),
)


@dataclass(frozen=True)
class FiatShamirFramework:
    """Concrete parameterisation plus the obligation ledger."""

    weight: int
    coefficient_bound: int
    degree: int
    quantum_queries: int
    transcripts_needed: int = 6   # 2 zeta branches x 3 x leaves
    challenge_rounds: int = 2     # zeta then x -- see multiround_qrom

    @property
    def challenge_space(self) -> int:
        return challenge_space_size(
            self.weight, self.coefficient_bound, self.degree
        )

    @property
    def soundness_bits(self) -> float:
        return soundness_error_bits(
            self.weight, self.coefficient_bound, self.degree
        )

    @property
    def forking_loss(self) -> float:
        """COMPUTED via Attema-Fehr-Kloss 2022, not the per-leaf placeholder.

        The old `forking_loss_bits(Q, leaves)` charged (leaves-1)*log2 Q =
        320 bits. AFK'22 bounds the whole multi-round FS transform by a
        single factor (Q+1): log2(Q+1) ~ 64 bits. See pqct/forking_bound.
        """
        from .forking_bound import forking_report
        return forking_report(self.quantum_queries).classical_loss_bits

    @property
    def qrom_loss(self) -> float:
        """QROM penalty BEYOND the classical loss (conservative
        measure-and-reprogram), so forking_loss + qrom_loss = total."""
        from .forking_bound import forking_report
        report = forking_report(self.quantum_queries)
        return report.qrom_loss_bits - report.classical_loss_bits

    @property
    def residual_bits_optimistic(self) -> float:
        """soundness - losses. OPTIMISTIC and NOT a security claim.

        Named 'optimistic' because it presumes every open obligation would
        be discharged with no additional loss, which is exactly what has NOT
        been established.
        """
        return self.soundness_bits - self.forking_loss - self.qrom_loss

    @property
    def open_obligations(self) -> tuple:
        return tuple(o for o in OBLIGATIONS if not o.discharged)

    @property
    def discharged_obligations(self) -> tuple:
        return tuple(o for o in OBLIGATIONS if o.discharged)

    @property
    def overall_status(self) -> str:
        if self.open_obligations:
            return (
                f"OPEN -- {len(self.open_obligations)} of {len(OBLIGATIONS)} "
                "obligations undischarged; no Fiat-Shamir security claim is "
                "made and residual_bits_optimistic is NOT a security level"
            )
        return (
            "all framework obligations code-evidenced or computed -- still "
            "requires external cryptanalytic review"
        )

    def summary(self) -> dict:
        return {
            "challenge_space_size": self.challenge_space,
            "soundness_bits_per_repetition": round(self.soundness_bits, 2),
            "quantum_queries_assumed": self.quantum_queries,
            "forking_loss_bits": round(self.forking_loss, 2),
            "qrom_reprogramming_loss_bits": round(self.qrom_loss, 2),
            "residual_bits_optimistic": round(self.residual_bits_optimistic, 2),
            "obligations_total": len(OBLIGATIONS),
            "obligations_discharged": len(self.discharged_obligations),
            "obligations_open": [o.name for o in self.open_obligations],
            "overall_status": self.overall_status,
            "warning": (
                "This is a FRAMEWORK, not a proof. residual_bits_optimistic "
                "presumes every open obligation is discharged at no extra "
                "loss -- precisely what has not been shown."
            ),
        }


def paper_framework(quantum_queries: int = 2 ** 64) -> FiatShamirFramework:
    """The framework at Gao's Section-8 challenge parameters (w=56, p=8, d=64)."""
    return FiatShamirFramework(
        weight=56, coefficient_bound=8, degree=64,
        quantum_queries=quantum_queries,
    )


__all__ = [
    "FiatShamirFramework",
    "FrameworkError",
    "OBLIGATIONS",
    "Obligation",
    "Status",
    "challenge_space_size",
    "forking_loss_bits",
    "paper_framework",
    "qrom_reprogramming_loss_bits",
    "soundness_error_bits",
]
