"""SHVZK simulator rejection stage (Gao Lemma 6 / Appendix B).

WHY THIS EXISTS
---------------
`pqct/protocol1_simulator.py` produces transcripts that satisfy the verifier
equations by construction, with NO rejection stage. That is not a simulator
in the SHVZK sense. The honest prover ABORTS on some runs, so the honest
transcript distribution is conditioned on acceptance; a simulator that never
aborts produces a distribution the honest prover demonstrably does not have,
and comparing the two is meaningless.

WHAT THE PAPER REQUIRES
-----------------------
Lemma 6 (paper line ~1985): for y ~ D_gamma^s and z = y + c with ||c|| < T,
an algorithm running Rej(z, c, phi, T)

  * outputs 1 with probability within 2^-100 of 1/mu(phi), where
        mu(phi) = exp(1/(2 phi) + 1/(2 phi^2))
  * and CONDITIONED on output 1, the distribution of z is within statistical
    distance 2^-100 of D_gamma^s.

Both halves matter, and they say something strong: the accepted honest
response looks like a FRESH sample from D_gamma that is independent of the
witness-dependent shift c. So the correct simulator is:

    1. sample the response directly from D_gamma^s   (no witness, no shift)
    2. accept with probability 1/mu(phi)             (witness-independent)
    3. on reject, abort exactly as the honest prover does

Step 2 is the piece that was missing. Without it the simulator's acceptance
RATE differs from the prover's, which is itself a distinguisher even when
every accepted transcript is individually perfect.

WHAT THIS MODULE DOES NOT DO
----------------------------
It does not prove SHVZK. Lemma 6's 2^-100 bounds are asymptotic statements
about the exact infinite discrete Gaussian D_gamma; this code uses the
finite-support reference sampler, so the realised distance is bounded by the
sampler's truncation error, not by 2^-100. It makes the simulator
STRUCTURALLY correct (right sampling law, right acceptance rate, real
aborts) so that empirical comparison is a fair test rather than a rigged one.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from .protocol1_sampling import (
    RejectionPolicy,
    SamplingError,
    XofByteSource,
    _uniform_unit,
)


class SimulatorRejectionError(ValueError):
    """Raised on inconsistent simulator rejection configuration."""


@dataclass(frozen=True)
class SimulatorRejection:
    """One witness-independent simulator acceptance decision."""

    accepted: bool
    acceptance_probability: Decimal
    draw: Decimal
    policy_mu: Decimal

    @property
    def target_rate(self) -> Decimal:
        return Decimal(1) / self.policy_mu


def simulator_acceptance_probability(policy: RejectionPolicy) -> Decimal:
    """1/mu(phi) -- the Lemma 6 acceptance rate.

    Deliberately does NOT depend on the response or any shift: the whole
    point of Lemma 6 is that the accepted distribution is independent of the
    witness-dependent shift, so the simulator must not consult one.
    """
    return Decimal(1) / policy.mu


def simulate_rejection(
    source: XofByteSource, policy: RejectionPolicy
) -> SimulatorRejection:
    """Draw one simulator accept/abort decision at rate 1/mu(phi)."""
    probability = simulator_acceptance_probability(policy)
    if not Decimal(0) < probability <= Decimal(1):
        raise SimulatorRejectionError(
            f"acceptance probability {probability} outside (0,1]"
        )
    draw = _uniform_unit(source)
    return SimulatorRejection(
        accepted=draw < probability,
        acceptance_probability=probability,
        draw=draw,
        policy_mu=policy.mu,
    )


@dataclass(frozen=True)
class RejectionRateComparison:
    """Empirical honest-vs-simulator acceptance-rate comparison."""

    honest_attempts: int
    honest_accepts: int
    simulator_attempts: int
    simulator_accepts: int
    target_rate: Decimal

    @property
    def honest_rate(self) -> Decimal:
        if not self.honest_attempts:
            return Decimal(0)
        return Decimal(self.honest_accepts) / Decimal(self.honest_attempts)

    @property
    def simulator_rate(self) -> Decimal:
        if not self.simulator_attempts:
            return Decimal(0)
        return Decimal(self.simulator_accepts) / Decimal(self.simulator_attempts)

    @property
    def rate_gap(self) -> Decimal:
        return abs(self.honest_rate - self.simulator_rate)

    def within(self, tolerance: Decimal) -> bool:
        """True when both rates sit within `tolerance` of 1/mu AND each other.

        Checking both matters: two runs could agree with each other while
        both drifting from the Lemma 6 target, which would mean the shared
        implementation is wrong rather than the comparison being fair.
        """
        return (
            abs(self.honest_rate - self.target_rate) <= tolerance
            and abs(self.simulator_rate - self.target_rate) <= tolerance
            and self.rate_gap <= tolerance
        )

    def summary(self) -> dict:
        return {
            "target_rate_1_over_mu": str(self.target_rate),
            "honest_rate": str(self.honest_rate),
            "simulator_rate": str(self.simulator_rate),
            "rate_gap": str(self.rate_gap),
            "honest": f"{self.honest_accepts}/{self.honest_attempts}",
            "simulator": f"{self.simulator_accepts}/{self.simulator_attempts}",
        }


def measure_simulator_rate(
    seed: bytes, policy: RejectionPolicy, samples: int
) -> tuple[int, int]:
    """Count simulator acceptances over `samples` independent draws."""
    if samples <= 0:
        raise SimulatorRejectionError("samples must be positive")
    accepts = 0
    for index in range(samples):
        source = XofByteSource(seed + b"|sim-rej|" + index.to_bytes(8, "big"))
        if simulate_rejection(source, policy).accepted:
            accepts += 1
    return samples, accepts


__all__ = [
    "RejectionRateComparison",
    "SimulatorRejection",
    "SimulatorRejectionError",
    "measure_simulator_rate",
    "simulate_rejection",
    "simulator_acceptance_probability",
]
