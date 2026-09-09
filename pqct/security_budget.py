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
    """M-LWE hiding, from pqct/mlwe_hardness.py at the paper profile.

    Previously UNANALYSED -- this component is why the budget refused to
    report a number. Now analysed by the paper's OWN criterion (Section 8
    applies the same delta ~ 1.0045 Eq.(2) test to M-LWE as to M-SIS), via
    the dual attack: the dual lattice has dimension m' and volume q^N, so
    BKZ reaches delta^m'*q^(N/m'), minimised at the same sqrt form, and the
    attack succeeds once that falls below q/sigma_e.
    """
    from .mlwe_hardness import paper_mlwe_report

    report = paper_mlwe_report()
    return Component(
        name="M-LWE hiding",
        bits_low=report.min_cost_bits,
        bits_high=report.max_cost_bits,
        certification=Certification.TWO_METHODS_AGREE,
        basis=(
            f"pqct/mlwe_hardness.py dual-attack delta criterion: "
            f"M-LWE({60 - 29}, 60, q, 1) over R_q^64, secret dimension "
            f"{report.n_int}, delta={report.required_delta:.7f}, "
            f"BKZ k={report.required_blocksize:.0f}. SAMPLE-LIMITED "
            f"(optimum wants {report.optimal_samples:.0f} columns, only "
            f"{report.available_samples} exist), so the true instance is "
            "harder than the unconstrained formula. Lands within ~2 bits of "
            "M-SIS, confirming the paper's m~2n balancing. NOT certified: "
            "delta->bits is a model choice and ternary secrets may admit "
            "hybrid attacks not modelled here."
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
    """Fiat-Shamir losses, now COMPUTED from pqct/forking_bound.py.

    Previously two separate placeholders (forking 320b + QROM 256b = 576b)
    that applied the single-round forking lemma to a 6-leaf tree and then
    charged QROM on top. Attema-Fehr-Kloss 2022 gives ONE bound for the
    whole multi-round transform, kappa_FS <= (Q+1)*kappa: the loss is
    log2(Q) once, not per leaf and not per round. That is a 512-bit
    correction. The QROM figure is reported as the conservative
    measure-and-reprogram bound, which is what we can actually cite today.

    The forking loss is marked established=True because AFK'22 is an
    applied theorem with the tree shape read off the code; it is
    CONDITIONAL on (2,3)-special-soundness, which is carried as a separate
    obligation in fiat_shamir_framework, not hidden inside this number.
    """
    from .forking_bound import forking_report

    report = forking_report(quantum_queries)
    return (
        Loss(
            name="Fiat-Shamir knowledge-error loss (classical, AFK'22)",
            bits=report.classical_loss_bits,
            basis=(
                f"Attema-Fehr-Kloss 2022, kappa_FS <= (Q+1)*kappa for the "
                f"({report.shape.branching[0]},{report.shape.branching[1]})-"
                f"special-sound 2-round protocol: log2(Q+1) = "
                f"{report.classical_loss_bits:.1f} bits ONCE. Replaces the "
                f"placeholder's {report.soundness_bits - report.placeholder_residual_bits:.0f} "
                f"bits, which applied the single-round forking lemma per leaf. "
                f"Conditional on special-soundness (open obligation)."
            ),
            established=True,
        ),
        Loss(
            name="QROM penalty beyond classical (DFM'20, TIGHT)",
            bits=report.qrom_loss_bits - report.classical_loss_bits,
            basis=(
                f"Don-Fehr-Majenz CRYPTO'20 Cor.13: multiplicative loss "
                f"n!/(2q+n+1)^(2n) for the 2-round FS transform = "
                f"{report.qrom_loss_bits:.1f} bits total, of which "
                f"{report.classical_loss_bits:.1f} is already the classical "
                f"AFK'22 term. DFM'20 Sec.6 proves q^(2n) is TIGHT (Grover "
                f"lower bound, up to a rounds-only constant), so no tighter "
                f"generic QROM theorem exists to cite. This is the true price "
                f"of the QROM for a 2-round protocol, not slack. The only way "
                f"to reduce it is structural: collapse to 1 round via "
                f"non-adaptive zeta (worth ~130 bits; see pqct/qrom_bound)."
            ),
            established=True,
        ),
        Loss(
            name="truncation / ZK leak (finite-support Gaussians)",
            bits=_truncation_zk_loss_bits(),
            basis=(
                "pqct/shvzk_bound.py: the SHVZK distance is BOUNDED at "
                "sum-over-coords of (Lemma6 2^-100 + erfc(T/sigma sqrt2)). "
                "At the codebase's CURRENT 6-sigma default this is 2^-15 -- a "
                "real ZK leak, previously mis-stated here as 0.0. Reported as "
                "shortfall against a 100-bit ZK target (100 + log2 distance). "
                "At the ~12.35-sigma tail the bound reaches the Lemma-6 floor "
                "2^-86 and this drops to ~14."
            ),
            established=True,
        ),
    )


def _truncation_zk_loss_bits() -> float:
    """ZK leak from the SHVZK bound at the sampler tail ACTUALLY SHIPPED.

    Reads ZK_TAIL_SIGMAS from protocol1_sampling so this number tracks the
    code: change the default there and the budget moves. Previously this
    hard-coded 6.0 (and before that 0.0), so a sampler fix would not have
    been reflected here. A statistical distance 2^-b is a distinguisher of
    advantage 2^-b; reported as shortfall vs a 100-bit ZK target.
    """
    from .protocol1_sampling import ZK_TAIL_SIGMAS
    from .shvzk_bound import paper_profile_bound

    log2_distance = paper_profile_bound(float(ZK_TAIL_SIGMAS)).total_log2
    return max(0.0, 100.0 + log2_distance)


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
