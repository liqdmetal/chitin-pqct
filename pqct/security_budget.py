"""Framework for an end-to-end bit-security claim.

WHAT THIS IS
------------
NOT a certified security level. It is the LEDGER a real claim would have to
balance, made executable: every component that contributes security, every
loss that subtracts from it, and an explicit refusal to output a number
while any component is uncertified.

The motivation is that "bit security" for a construction like this is not
one number from one tool. It is a minimum over independent assumptions,
minus reduction losses:

    security = min(
        M-SIS binding hardness,        # commitment cannot be double-opened
        M-LWE hiding hardness,         # commitment reveals nothing
        signature strength,            # authorization cannot be forged
        challenge-space soundness,     # cheating prover cannot guess
    ) - reduction_losses

A single weak component caps the whole thing, and a large reduction loss can
erase a comfortable-looking minimum -- which is exactly what the Fiat-Shamir
framework found (256 bits of soundness minus 128 forking minus 128 QROM
leaves ~0 at Q = 2^64).

WHAT IS ACTUALLY KNOWN HERE
---------------------------
  * M-SIS: two independent methods agree on the root-Hermite factor to
    ~3e-4 and give 92-117 bits depending on the cost model
    (pqct/msis_hardness.py). NOT certified: the real instance has mixed
    per-column bounds a scalar bound cannot express, and delta -> bits is a
    model choice.
  * ML-DSA-65: a NIST-standardised parameter set at security category 3,
    conventionally quoted around 192 bits classical. This is the one
    component with an external, published analysis, and it is NOT ours.
  * Challenge soundness: 256 bits, computed exactly.
  * M-LWE hiding: NOT analysed anywhere in this repository.

So the binding minimum sits at 92-117 bits BEFORE losses, the hiding term is
unknown, and the Fiat-Shamir losses are large. Any of those three facts is
enough to block a claim.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum


class BudgetError(ValueError):
    """Raised on inconsistent security-budget inputs."""


class Certification(Enum):
    """How well-established a component's number is."""

    EXTERNAL_STANDARD = "external-standard"   # NIST/published, not ours
    TWO_METHODS_AGREE = "two-methods-agree"   # our tools cross-check
    COMPUTED_EXACT = "computed-exact"         # exact combinatorics
    UNANALYSED = "unanalysed"                 # nobody has done it


@dataclass(frozen=True)
class Component:
    """One security-providing assumption."""

    name: str
    bits_low: float
    bits_high: float
    certification: Certification
    basis: str

    def __post_init__(self) -> None:
        if self.bits_low > self.bits_high:
            raise BudgetError(f"{self.name}: low bound exceeds high bound")

    @property
    def certified(self) -> bool:
        return self.certification is not Certification.UNANALYSED

    @property
    def is_range(self) -> bool:
        return self.bits_high > self.bits_low


@dataclass(frozen=True)
class Loss:
    """One reduction loss that subtracts from the minimum."""

    name: str
    bits: float
    basis: str
    established: bool


def msis_component(bits_low: float = 91.5, bits_high: float = 117.3
                   ) -> Component:
    """M-SIS binding, from pqct/msis_hardness.py at the paper profile."""
    return Component(
        name="M-SIS binding",
        bits_low=bits_low,
        bits_high=bits_high,
        certification=Certification.TWO_METHODS_AGREE,
        basis=(
            "pqct/msis_hardness.py delta-criterion (BKZ k=345, delta="
            "1.0044) and the real lattice-estimator agree on delta to "
            "~3e-4; range spans ADPS16-quantum (91.5) to BDGL16-classical "
            "(117.3). NOT certified: mixed per-column bounds unmodelled, "
            "delta->bits is a model choice."
        ),
    )


def mlwe_component() -> Component:
    """M-LWE hiding -- nobody has analysed this here."""
    return Component(
        name="M-LWE hiding",
        bits_low=0.0,
        bits_high=0.0,
        certification=Certification.UNANALYSED,
        basis=(
            "NOT ANALYSED. Gao Lemma 1 requires M-LWE(m-n, m, q, B) hard for "
            "the HMC to be computationally hiding. No estimate exists in "
            "this repository; hiding is what keeps committed amounts "
            "confidential, so this gap is as serious as the binding one."
        ),
    )


def signature_component() -> Component:
    """ML-DSA-65: external, standardised, and not our analysis."""
    return Component(
        name="ML-DSA-65 signature",
        bits_low=192.0,
        bits_high=192.0,
        certification=Certification.EXTERNAL_STANDARD,
        basis=(
            "NIST FIPS 204 security category 3. The ONLY component with a "
            "published external analysis. Used for authorization in "
            "pqct/authorization.py."
        ),
    )


def challenge_soundness_component(bits: float = 256.04) -> Component:
    return Component(
        name="challenge-space soundness",
        bits_low=bits,
        bits_high=bits,
        certification=Certification.COMPUTED_EXACT,
        basis=(
            "|C_{w,p}| = C(64,56)*16^56 computed exactly in "
            "pqct/fiat_shamir_framework.py."
        ),
    )


def default_components() -> tuple:
    return (
        msis_component(),
        mlwe_component(),
        signature_component(),
        challenge_soundness_component(),
    )


def default_losses(quantum_queries: int = 2 ** 64) -> tuple:
    log_q = math.log2(quantum_queries)
    return (
        Loss(
            name="forking / rewinding (3 transcripts)",
            bits=2.0 * log_q,
            basis=(
                "(t-1)*log2(Q) with t=3, from "
                "pqct/fiat_shamir_framework.forking_loss_bits."
            ),
            established=False,
        ),
        Loss(
            name="QROM adaptive reprogramming",
            bits=2.0 * log_q,
            basis=(
                "2*log2(Q) conservative bookkeeping; WHICH theorem applies "
                "is itself an open obligation."
            ),
            established=False,
        ),
        Loss(
            name="truncation (finite-support Gaussians)",
            bits=0.0,
            basis=(
                "pqct/truncation_distance.py: exactly erfc(T/(sigma*sqrt2)) "
                "per coordinate, composed linearly. At the tails required "
                "for 2^-100 this is negligible against the other terms, but "
                "the CURRENT 6-sigma default gives only ~2^-29 per "
                "coordinate."
            ),
            established=True,
        ),
    )


@dataclass(frozen=True)
class SecurityBudget:
    """The full ledger: components, losses, and a refusal to overstate."""

    components: tuple
    losses: tuple

    @property
    def certified_components(self) -> tuple:
        return tuple(c for c in self.components if c.certified)

    @property
    def uncertified_components(self) -> tuple:
        return tuple(c for c in self.components if not c.certified)

    @property
    def minimum_low(self) -> float:
        """Worst-case minimum over CERTIFIED components only."""
        certified = self.certified_components
        if not certified:
            return 0.0
        return min(c.bits_low for c in certified)

    @property
    def minimum_high(self) -> float:
        certified = self.certified_components
        if not certified:
            return 0.0
        return min(c.bits_high for c in certified)

    @property
    def total_loss(self) -> float:
        return sum(l.bits for l in self.losses)

    @property
    def residual_low(self) -> float:
        return self.minimum_low - self.total_loss

    @property
    def residual_high(self) -> float:
        return self.minimum_high - self.total_loss

    @property
    def binding_component(self) -> Component:
        """Which certified component caps the minimum."""
        return min(self.certified_components, key=lambda c: c.bits_low)

    @property
    def claimable(self) -> bool:
        """A number may be claimed only if EVERY component is certified,
        every loss is established, and the residual is positive."""
        return (
            not self.uncertified_components
            and all(l.established for l in self.losses)
            and self.residual_low > 0.0
        )

    @property
    def verdict(self) -> str:
        reasons = []
        if self.uncertified_components:
            names = ", ".join(c.name for c in self.uncertified_components)
            reasons.append(f"uncertified component(s): {names}")
        unestablished = [l.name for l in self.losses if not l.established]
        if unestablished:
            reasons.append(f"unestablished loss(es): {', '.join(unestablished)}")
        if self.residual_low <= 0.0:
            reasons.append(
                f"residual is non-positive ({self.residual_low:.1f} bits)"
            )
        if not reasons:
            return (
                f"all components certified; residual "
                f"{self.residual_low:.1f}-{self.residual_high:.1f} bits "
                "-- still requires external review"
            )
        return "NO CLAIM: " + "; ".join(reasons)

    def summary(self) -> dict:
        return {
            "components": [
                {
                    "name": c.name,
                    "bits": (
                        f"{c.bits_low:.1f}-{c.bits_high:.1f}"
                        if c.is_range else f"{c.bits_low:.1f}"
                    ),
                    "certification": c.certification.value,
                    "certified": c.certified,
                }
                for c in self.components
            ],
            "losses": [
                {"name": l.name, "bits": round(l.bits, 1),
                 "established": l.established}
                for l in self.losses
            ],
            "capped_by": self.binding_component.name if self.certified_components else None,
            "minimum_over_certified": (
                f"{self.minimum_low:.1f}-{self.minimum_high:.1f}"
            ),
            "total_loss_bits": round(self.total_loss, 1),
            "residual_bits": f"{self.residual_low:.1f}-{self.residual_high:.1f}",
            "claimable": self.claimable,
            "verdict": self.verdict,
        }


def paper_budget(quantum_queries: int = 2 ** 64) -> SecurityBudget:
    return SecurityBudget(
        components=default_components(),
        losses=default_losses(quantum_queries),
    )


__all__ = [
    "BudgetError",
    "Certification",
    "Component",
    "Loss",
    "SecurityBudget",
    "challenge_soundness_component",
    "default_components",
    "default_losses",
    "mlwe_component",
    "msis_component",
    "paper_budget",
    "signature_component",
]
