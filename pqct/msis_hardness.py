"""M-SIS hardness analysis following Gao's OWN criterion (Eq.2), plus a
modern cross-check -- and an honest account of where they disagree.

WHY THIS MODULE EXISTS
----------------------
Blocker item 5 (certified bit-security) stalled on a contradiction:

  * `tools/sage_sis_estimate.py` (real lattice-estimator) reported 83-113
    bits for the paper profile.
  * A Gaussian-heuristic gate said the same instance was "trivially easy by
    counting" (gamma/GH ~ 5e10), which would mean ~0 bits.
  * The paper itself claims its Section-8 setting "suffices the 128-bit
    security of partially amortized binary proof" at S<=2.

Three answers, three methods. Rather than pick the flattering one, this
module implements the paper's ACTUAL criterion so the disagreement can be
localised.

THE PAPER'S CRITERION (Eq.2)
----------------------------
M-SIS(n, m, q, beta) is treated as hard when

    min{ q, 2^(2*sqrt(n*d*log2(q)*log2(delta))) } > beta

The exponential term is not a Gaussian-heuristic statement. It is the
*optimised-sublattice* result: an attacker holding many columns may DROP
columns, and for a q-ary lattice of rank n*d with modulus q, BKZ achieving
root-Hermite factor delta finds a vector of length

    min over m' of   delta^m' * q^(n*d/m')

minimised at m' = sqrt(n*d*log2(q)/log2(delta)), giving exactly
2^(2*sqrt(n*d*log2(q)*log2(delta))).

This resolves the Gaussian-heuristic paradox: evaluating GH at the FULL
column count (7936) is the wrong dimension. Short vectors do exist there,
but the attacker's cost is governed by the OPTIMAL sub-dimension (~3800 for
this profile -- which is close to the `d` the estimator itself reported,
3378-4008, a reassuring independent agreement).

WHAT REMAINS GENUINELY OPEN
---------------------------
The criterion is delta-based, and delta -> bit-security is a MODEL CHOICE.
The paper inherits delta=1.0045 <-> "128-bit" from MatRiCT [EZS+19], a
legacy mapping. Modern cost models (ADPS16 core-SVP 0.292*k, MATZOV 2022)
convert the same delta to a very different bit count. So:

  * Eq.(2) HOLDS for the paper profile (verified, see paper_bounds/tests).
  * The paper's own criterion is therefore satisfied.
  * But "128-bit" rests on the legacy delta<->bits mapping, and a modern
    model applied to the same delta gives a different number.

Nothing here certifies a bit-security level. It makes the disagreement
precise and attributable, which is the prerequisite for a lattice
cryptographer to settle it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

TWO_PI_E = 2.0 * math.pi * math.e


class HardnessError(ValueError):
    """Raised on non-physical hardness-analysis inputs."""


def root_hermite_from_blocksize(k: float) -> float:
    """delta(k) for BKZ with block size k (Chen-Nguyen / GSA form).

        delta = ( (k / (2*pi*e)) * (pi*k)^(1/k) )^( 1/(2*(k-1)) )

    Valid for k >= 50; below that BKZ is not in the asymptotic regime and
    this formula should not be trusted.
    """
    if k <= 1:
        raise HardnessError("BKZ block size must exceed 1")
    inner = (k / TWO_PI_E) * (math.pi * k) ** (1.0 / k)
    return inner ** (1.0 / (2.0 * (k - 1.0)))


def blocksize_for_root_hermite(delta: float, *, lo: float = 2.0,
                               hi: float = 100_000.0) -> float:
    """Invert delta(k) numerically. delta decreases as k grows."""
    if delta <= 1.0:
        raise HardnessError("root-Hermite factor must exceed 1")
    if root_hermite_from_blocksize(hi) > delta:
        raise HardnessError(
            f"delta={delta} unreachable below block size {hi:.0f}"
        )
    for _ in range(300):
        mid = 0.5 * (lo + hi)
        if root_hermite_from_blocksize(mid) > delta:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def optimal_sublattice_dimension(n_int: int, log2_q: float,
                                 log2_delta: float) -> float:
    """m' = sqrt(n_int * log2(q) / log2(delta)) -- the attacker's best
    column count after dropping the rest."""
    if log2_delta <= 0:
        raise HardnessError("log2(delta) must be positive")
    if n_int <= 0 or log2_q <= 0:
        raise HardnessError("n_int and log2(q) must be positive")
    return math.sqrt(n_int * log2_q / log2_delta)


def achievable_length_log2(n_int: int, log2_q: float,
                           log2_delta: float) -> float:
    """log2 of 2^(2*sqrt(n*d*log2 q*log2 delta)) -- the shortest vector BKZ
    at this delta can reach in the optimal sub-dimension."""
    return 2.0 * math.sqrt(n_int * log2_q * log2_delta)


def required_root_hermite(log2_beta: float, n_int: int,
                          log2_q: float) -> float:
    """Invert Eq.(2)'s exponential: the delta an attacker NEEDS to reach a
    vector of length beta.

        log2(beta) = 2*sqrt(n*d*log2 q*log2 delta)
     => log2(delta) = log2(beta)^2 / (4*n*d*log2 q)

    A SMALLER delta means stronger reduction, i.e. a harder attack.
    """
    if log2_beta <= 0:
        raise HardnessError("log2(beta) must be positive")
    log2_delta = (log2_beta * log2_beta) / (4.0 * n_int * log2_q)
    return 2.0 ** log2_delta


# Cost models: bits of work for BKZ with block size k.
# core-SVP style: one SVP call in dimension k, ignoring the polynomial
# number of tours (deliberately conservative / attacker-favouring).
COST_MODELS = {
    "ADPS16_classical": lambda k: 0.292 * k,
    "ADPS16_quantum": lambda k: 0.265 * k,
    "BDGL16_classical": lambda k: 0.292 * k + 16.4,
    "MATZOV22_quantum": lambda k: 0.2645 * k + 16.4 + math.log2(k),
    "legacy_delta_1_0045_is_128bit": None,  # marker, handled separately
}


@dataclass(frozen=True)
class MSISHardnessReport:
    """Full delta-criterion analysis for one M-SIS instance."""

    n_int: int
    log2_q: float
    log2_beta: float
    beta_lt_q: bool
    required_delta: float
    required_log2_delta: float
    required_blocksize: float
    optimal_dimension: float
    eq2_rhs_log2_at_paper_delta: float
    eq2_holds_at_paper_delta: bool
    costs_bits: dict
    notes: tuple

    @property
    def min_cost_bits(self) -> float:
        values = [v for v in self.costs_bits.values() if v is not None]
        return min(values) if values else float("nan")


PAPER_DELTA = 1.0045  # Gao/MatRiCT's assumed "128-bit" root-Hermite factor


def analyze_msis(*, n_module: int, d: int, q: int, beta: float,
                 paper_delta: float = PAPER_DELTA) -> MSISHardnessReport:
    """Run the paper's delta-criterion and modern cost models side by side.

    n_module * d = the integer rank n*d used in Eq.(2). beta is the M-SIS
    solution norm bound the adversary must reach (for HMC binding this is
    2*gamma, since two openings each within gamma differ by at most 2*gamma).
    """
    if min(n_module, d) <= 0 or q <= 1:
        raise HardnessError("invalid ring/modulus parameters")
    if beta <= 0:
        raise HardnessError("beta must be positive")

    n_int = n_module * d
    log2_q = math.log2(q)
    log2_beta = math.log2(beta)

    required_delta = required_root_hermite(log2_beta, n_int, log2_q)
    required_log2_delta = math.log2(required_delta)
    optimal_dim = optimal_sublattice_dimension(n_int, log2_q, required_log2_delta)

    # Eq.(2) evaluated at the paper's assumed delta.
    rhs_log2 = achievable_length_log2(n_int, log2_q, math.log2(paper_delta))
    eq2_rhs_log2 = min(log2_q, rhs_log2)
    eq2_holds = eq2_rhs_log2 > log2_beta

    notes = []
    if beta >= q:
        notes.append(
            "beta >= q: Eq.(2) cannot hold; a norm-q vector always exists"
        )
    if beta > q / 4:
        notes.append(
            f"beta is within a small factor of q (beta/q = {beta/q:.3f}); "
            "q-ary structure dominates and estimates are fragile here"
        )

    costs = {}
    try:
        blocksize = blocksize_for_root_hermite(required_delta)
    except HardnessError as error:
        blocksize = float("nan")
        notes.append(f"block size unresolved: {error}")
    if not math.isnan(blocksize):
        for name, fn in COST_MODELS.items():
            costs[name] = None if fn is None else fn(blocksize)
        if blocksize < 50:
            notes.append(
                f"block size {blocksize:.0f} < 50: outside BKZ's asymptotic "
                "regime, core-SVP costs are not meaningful"
            )

    notes.append(
        "delta -> bits is a MODEL CHOICE. The paper inherits "
        "delta=1.0045 <-> 128-bit from MatRiCT [EZS+19]; modern core-SVP "
        "models give a different bit count for the same delta. Eq.(2) "
        "holding is NOT the same as a certified bit-security level."
    )
    notes.append(
        "A Gaussian-heuristic check at the FULL column count is the wrong "
        "dimension: attackers drop columns, so hardness is governed by the "
        f"optimal sub-dimension (~{optimal_dim:.0f} here), not m_total."
    )

    return MSISHardnessReport(
        n_int=n_int,
        log2_q=log2_q,
        log2_beta=log2_beta,
        beta_lt_q=beta < q,
        required_delta=required_delta,
        required_log2_delta=required_log2_delta,
        required_blocksize=blocksize,
        optimal_dimension=optimal_dim,
        eq2_rhs_log2_at_paper_delta=eq2_rhs_log2,
        eq2_holds_at_paper_delta=eq2_holds,
        costs_bits=costs,
        notes=tuple(notes),
    )


__all__ = [
    "COST_MODELS",
    "HardnessError",
    "MSISHardnessReport",
    "PAPER_DELTA",
    "achievable_length_log2",
    "analyze_msis",
    "blocksize_for_root_hermite",
    "optimal_sublattice_dimension",
    "required_root_hermite",
    "root_hermite_from_blocksize",
]
