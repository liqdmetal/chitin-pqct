"""M-LWE hiding hardness -- the gap the security budget surfaced.

WHY THIS EXISTS
---------------
`pqct/security_budget.py` reported M-LWE hiding as UNANALYSED, and that was
correct: nothing in this repository estimated it. Gao Lemma 1 requires

    M-LWE(m - n, m, q, B) hard  =>  the HMC is computationally HIDING

and hiding is what keeps committed amounts confidential. A binding-only
analysis says a commitment cannot be double-opened; it says nothing about
whether the commitment leaks the amount. For a confidential-transaction
scheme that is the more user-visible property.

THE PAPER'S OWN CRITERION
-------------------------
Section 8 (line ~1662): "the security of M-SIS increases with n whereas the
security of M-LWE increases with m - n. Thus, we balance the security
aspects to choose parameters such that m ~ 2n. Furthermore, MatRiCT and
MatRiCT+ aim for the root Hermite factor of delta ~ 1.0045 in Equation (2)
for BOTH M-LWE and M-SIS."

So the paper applies the SAME delta criterion to both problems. That is what
makes this module directly comparable to `pqct/msis_hardness.py` rather than
a separate methodology.

THE DUAL-ATTACK REDUCTION TO EQ.(2) FORM
----------------------------------------
For LWE with secret dimension N, modulus q and m' samples, the dual lattice

    L^perp = { v in Z^m' : A^T v == 0 mod q }

has dimension m' and volume q^N. BKZ at root-Hermite factor delta finds a
vector of length delta^m' * q^(N/m'), minimised over m' at
m' = sqrt(N*log2(q)/log2(delta)), giving

    achievable_length = 2^( 2*sqrt( N * log2(q) * log2(delta) ) )

-- structurally IDENTICAL to Eq.(2)'s exponential, with N = (m-n)*d in place
of n*d. A short dual vector v distinguishes LWE from uniform with advantage
about exp(-pi*(length*sigma_e/q)^2), so the attack works once

    achievable_length <~ q / sigma_e.

Security therefore requires

    2^( 2*sqrt( N*log2 q*log2 delta ) )  >  q / sigma_e

which is Eq.(2) with beta := q / sigma_e. The whole M-SIS delta machinery
applies unchanged, and `pqct.msis_hardness.required_root_hermite` is reused
rather than reimplemented.

THE SAMPLE-LIMIT SUBTLETY (this one bites)
------------------------------------------
The optimum above assumes the attacker may use as many samples as the
formula wants. Here the HMC exposes only m*d = 3840 columns, while the
optimum at delta = 1.0045 wants m' ~ 3870. When the optimum EXCEEDS the
available samples, the attacker is forced to m' = available, the achievable
length is LONGER (delta^m'*q^(N/m') evaluated off-optimum), and the instance
is HARDER than the unconstrained formula suggests. Reporting the
unconstrained number in that regime would understate security -- which is
the safe direction, but it is still wrong, so both are computed and the
binding regime is stated explicitly.

HONEST SCOPE
------------
This is the paper's own criterion, evaluated correctly, plus a modern
cost-model conversion. It is NOT a certified bit-security level: delta ->
bits remains a model choice, the ternary-secret distribution may admit
better-than-generic attacks (hybrid / combinatorial), and no external review
has happened. It moves M-LWE from "unanalysed" to "analysed, uncertified".
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .msis_hardness import (
    COST_MODELS,
    HardnessError,
    blocksize_for_root_hermite,
    required_root_hermite,
)

PAPER_DELTA = 1.0045


def uniform_ternary_sigma(bound: int = 1) -> float:
    """Std dev of the uniform distribution on {-B,...,B}.

    Variance of uniform on 2B+1 consecutive integers centred at 0 is
    B*(B+1)/3, so B=1 (ternary) gives sqrt(2/3) ~ 0.8165.
    """
    if bound < 1:
        raise HardnessError("bound must be at least 1")
    return math.sqrt(bound * (bound + 1) / 3.0)


def distinguishing_beta(q: int, sigma_e: float) -> float:
    """beta = q / sigma_e -- the dual-vector length at which LWE breaks."""
    if q <= 1:
        raise HardnessError("modulus must exceed 1")
    if sigma_e <= 0:
        raise HardnessError("error sigma must be positive")
    return q / sigma_e


def achievable_length_log2_at(n_int: int, log2_q: float, log2_delta: float,
                              samples: int) -> float:
    """log2( delta^samples * q^(n_int/samples) ) at a FIXED sample count."""
    if samples <= 0:
        raise HardnessError("sample count must be positive")
    return samples * log2_delta + log2_q * n_int / samples


def optimal_samples(n_int: int, log2_q: float, log2_delta: float) -> float:
    if log2_delta <= 0:
        raise HardnessError("log2(delta) must be positive")
    return math.sqrt(n_int * log2_q / log2_delta)


@dataclass(frozen=True)
class MLWEHardnessReport:
    """M-LWE hiding analysis for one parameter set."""

    n_int: int
    available_samples: int
    log2_q: float
    sigma_e: float
    log2_beta: float
    required_delta: float
    required_blocksize: float
    optimal_samples: float
    samples_are_limiting: bool
    achievable_log2_at_paper_delta: float
    achievable_log2_limited: float
    criterion_holds_at_paper_delta: bool
    costs_bits: dict
    notes: tuple

    @property
    def min_cost_bits(self) -> float:
        values = [v for v in self.costs_bits.values() if v is not None]
        return min(values) if values else float("nan")

    @property
    def max_cost_bits(self) -> float:
        values = [v for v in self.costs_bits.values() if v is not None]
        return max(values) if values else float("nan")

    def summary(self) -> dict:
        return {
            "n_int_secret_dimension": self.n_int,
            "available_samples": self.available_samples,
            "optimal_samples": round(self.optimal_samples, 1),
            "samples_are_limiting": self.samples_are_limiting,
            "sigma_e": round(self.sigma_e, 6),
            "log2_beta": round(self.log2_beta, 3),
            "required_delta": round(self.required_delta, 7),
            "required_blocksize": round(self.required_blocksize, 1),
            "criterion_holds_at_paper_delta": self.criterion_holds_at_paper_delta,
            "bits_range": (
                f"{self.min_cost_bits:.1f}-{self.max_cost_bits:.1f}"
                if self.costs_bits else "n/a"
            ),
            "costs_bits": {k: (None if v is None else round(v, 1))
                           for k, v in self.costs_bits.items()},
            "notes": list(self.notes),
        }


def analyze_mlwe(*, secret_rank: int, samples_rank: int, d: int, q: int,
                 bound: int = 1, paper_delta: float = PAPER_DELTA
                 ) -> MLWEHardnessReport:
    """Analyse M-LWE(secret_rank, samples_rank, q, bound) over R_q of degree d.

    For Gao's HMC use secret_rank = m - n and samples_rank = m (Lemma 1).
    """
    if min(secret_rank, samples_rank, d) <= 0:
        raise HardnessError("ranks and degree must be positive")
    if samples_rank < secret_rank:
        raise HardnessError("samples_rank must be at least secret_rank")

    n_int = secret_rank * d
    available = samples_rank * d
    log2_q = math.log2(q)
    sigma_e = uniform_ternary_sigma(bound)
    beta = distinguishing_beta(q, sigma_e)
    log2_beta = math.log2(beta)

    required_delta = required_root_hermite(log2_beta, n_int, log2_q)
    log2_required = math.log2(required_delta)
    opt = optimal_samples(n_int, log2_q, log2_required)
    limiting = opt > available

    log2_paper_delta = math.log2(paper_delta)
    opt_at_paper = optimal_samples(n_int, log2_q, log2_paper_delta)
    unconstrained = 2.0 * math.sqrt(n_int * log2_q * log2_paper_delta)
    limited = achievable_length_log2_at(
        n_int, log2_q, log2_paper_delta, min(available, max(1, int(opt_at_paper)))
    )
    # The attacker takes the SHORTER reachable vector, but cannot exceed the
    # available sample count, so the operative length is the limited one.
    operative = limited if opt_at_paper > available else unconstrained
    holds = operative > log2_beta

    notes = []
    if limiting:
        notes.append(
            f"SAMPLE-LIMITED: the optimal dual dimension {opt:.0f} exceeds the "
            f"{available} columns the HMC exposes, so the attacker is forced "
            "off-optimum and the instance is HARDER than the unconstrained "
            "formula suggests."
        )
    if opt_at_paper > available:
        notes.append(
            f"at the paper's delta the optimum wants {opt_at_paper:.0f} samples "
            f"but only {available} exist; the limited length "
            f"2^{limited:.2f} is used instead of 2^{unconstrained:.2f}."
        )
    notes.append(
        "beta = q/sigma_e is the DISTINGUISHING threshold for the dual "
        "attack, not a solution-norm bound as in M-SIS. Same Eq.(2) form, "
        "different meaning."
    )
    notes.append(
        "Ternary secrets (B=1) may admit hybrid/combinatorial attacks that "
        "beat this generic dual-attack estimate; not modelled here."
    )
    notes.append(
        "delta -> bits is a MODEL CHOICE, as for M-SIS. No certified "
        "bit-security level is claimed."
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

    return MLWEHardnessReport(
        n_int=n_int,
        available_samples=available,
        log2_q=log2_q,
        sigma_e=sigma_e,
        log2_beta=log2_beta,
        required_delta=required_delta,
        required_blocksize=blocksize,
        optimal_samples=opt,
        samples_are_limiting=limiting,
        achievable_log2_at_paper_delta=unconstrained,
        achievable_log2_limited=limited,
        criterion_holds_at_paper_delta=holds,
        costs_bits=costs,
        notes=tuple(notes),
    )


def paper_mlwe_report() -> MLWEHardnessReport:
    """Gao Section 8: M-LWE(m-n, m, q, B) = M-LWE(31, 60, q, 1), d=64."""
    return analyze_mlwe(
        secret_rank=60 - 29, samples_rank=60, d=64,
        q=2 ** 49 - 2 ** 18 + 2 ** 9 + 1, bound=1,
    )


__all__ = [
    "MLWEHardnessReport",
    "PAPER_DELTA",
    "achievable_length_log2_at",
    "analyze_mlwe",
    "distinguishing_beta",
    "optimal_samples",
    "paper_mlwe_report",
    "uniform_ternary_sigma",
]
