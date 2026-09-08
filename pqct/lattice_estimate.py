"""Conservative core-SVP-hardness estimate for M-SIS/M-LWE (NOT the real tool)."""

from __future__ import annotations

from dataclasses import dataclass
from math import log2, pi, e


class LatticeEstimateError(ValueError):
    """Invalid estimator input."""


# Core-SVP bit-security cost per BKZ block of dimension beta.
# Constants from Albrecht/Player/Scott 2015 "On the concrete hardness
# of Learning with Errors" (sieving costs), as used by the NIST PQC
# submissions' "core-SVP" methodology. NOT independently re-derived
# here -- cited constants only.
_CLASSICAL_SIEVE_CONST = 0.292
_QUANTUM_SIEVE_CONST = 0.265
_PARANOID_SIEVE_CONST = 0.2075


def delta_from_beta(beta: float) -> float:
    """Root Hermite factor for BKZ blocksize beta (Chen-Nguyen 2011 approx).

    delta(beta) = ((pi*beta)^(1/beta) * beta / (2*pi*e)) ** (1/(2*(beta-1)))
    Valid asymptotically for beta >= ~50; used here only as a standard,
    widely-cited estimator input, not a fresh derivation.
    """
    if beta <= 1:
        raise LatticeEstimateError("beta must exceed 1")
    inner = ((pi * beta) ** (1.0 / beta)) * beta / (2.0 * pi * e)
    return inner ** (1.0 / (2.0 * (beta - 1.0)))


def beta_from_delta(delta: float, *, lo: float = 50.0, hi: float = 200000.0) -> float:
    """Invert delta_from_beta via bisection (delta is decreasing in beta).

    Restricted to beta>=50, the range where the Chen-Nguyen approximation
    is monotonic and considered valid (see delta_from_beta docstring); the
    function is non-monotonic and asymptotically invalid below that.
    """
    if delta <= 1.0:
        raise LatticeEstimateError("delta must exceed 1.0")
    if lo < 50.0:
        raise LatticeEstimateError(
            "lo must be >= 50 (formula invalid/non-monotonic below this)"
        )
    if delta_from_beta(hi) > delta:
        raise LatticeEstimateError(
            "delta too large for search range; increase hi"
        )
    if delta_from_beta(lo) < delta:
        raise LatticeEstimateError(
            "delta too large for beta>=50 domain (would need beta<50, "
            "where the Chen-Nguyen approximation is not monotonic/valid)"
        )
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if delta_from_beta(mid) > delta:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def core_svp_bits(beta: float, *, model: str = "classical") -> float:
    """Core-SVP bit-hardness cost 2^(c*beta) for a BKZ-beta sieve call.

    model in {"classical","quantum","paranoid"} selects the sieving
    constant c (Albrecht/Player/Scott 2015; NIST PQC core-SVP convention).
    This ignores polynomial pre-factors, the number of BKZ tours, and
    memory-access cost models. Omitting those factors under-costs the
    attacker, so this yields a LOWER BOUND on required work -- i.e. a
    conservative (non-overclaiming) security estimate, matching the
    "core-SVP hardness" convention used by NIST PQC submissions.
    """
    if beta <= 0:
        raise LatticeEstimateError("beta must be positive")
    constants = {
        "classical": _CLASSICAL_SIEVE_CONST,
        "quantum": _QUANTUM_SIEVE_CONST,
        "paranoid": _PARANOID_SIEVE_CONST,
    }
    if model not in constants:
        raise LatticeEstimateError(f"unknown model: {model}")
    return constants[model] * beta


@dataclass(frozen=True)
class SISHardnessEstimate:
    """End-to-end estimate chaining Gao Eq.(2) -> BKZ beta -> core-SVP bits."""

    n: int
    d: int
    q: int
    beta_bound: int
    required_delta: float
    bkz_blocksize: float
    classical_bits: float
    quantum_bits: float
    paranoid_bits: float
    is_lower_bound: bool = False


def estimate_sis_hardness(
    n: int,
    d: int,
    q: int,
    beta_bound: int,
) -> SISHardnessEstimate:
    """Estimate M-SIS(n, *, q, beta_bound) hardness via Gao's own Eq.(2).

    Solves min{q, 2^(2*sqrt(n*d*log2(q)*log2(delta)))} = beta_bound for
    the root Hermite factor delta (the SAME relation Gao's paper uses for
    the HMC binding parameter check), converts delta to the BKZ blocksize
    an attacker would need (Chen-Nguyen 2011), then reports core-SVP bit
    costs (Albrecht/Player/Scott 2015 sieving constants). This is a
    standard, widely-used ESTIMATION METHODOLOGY, not a substitute for a
    verified tool such as the Albrecht/Player/Scott `lattice-estimator`,
    and it ignores many refinements that tool includes (e.g. dual attacks,
    hybrid attacks, BKZ 2.0 simulators, exact GSA slope).
    """
    if n <= 0 or d <= 0 or q <= 2:
        raise LatticeEstimateError("n, d, q must be positive with q>2")
    if beta_bound <= 0:
        raise LatticeEstimateError("beta_bound must be positive")
    log2_beta = log2(float(beta_bound))
    denominator = 4.0 * n * d * log2(float(q))
    if denominator <= 0:
        raise LatticeEstimateError("invalid n/d/q for hardness estimate")
    required_log2_delta = (log2_beta ** 2) / denominator
    required_delta = 2.0 ** required_log2_delta
    max_beta = 200000.0
    min_beta = 50.0
    if required_delta <= delta_from_beta(max_beta):
        return SISHardnessEstimate(
            n=n, d=d, q=q, beta_bound=beta_bound,
            required_delta=required_delta,
            bkz_blocksize=max_beta,
            classical_bits=core_svp_bits(max_beta, model="classical"),
            quantum_bits=core_svp_bits(max_beta, model="quantum"),
            paranoid_bits=core_svp_bits(max_beta, model="paranoid"),
            is_lower_bound=True,
        )
    if required_delta >= delta_from_beta(min_beta):
        raise LatticeEstimateError(
            "beta_bound too large: required attack cost falls below the "
            "formula's valid beta>=50 domain -- this estimator cannot "
            "produce a meaningful number for such a weak parameter choice"
        )
    bkz_beta = beta_from_delta(required_delta)
    return SISHardnessEstimate(
        n=n, d=d, q=q, beta_bound=beta_bound,
        required_delta=required_delta,
        bkz_blocksize=bkz_beta,
        classical_bits=core_svp_bits(bkz_beta, model="classical"),
        quantum_bits=core_svp_bits(bkz_beta, model="quantum"),
        paranoid_bits=core_svp_bits(bkz_beta, model="paranoid"),
    )


__all__ = [
    "LatticeEstimateError",
    "SISHardnessEstimate",
    "beta_from_delta",
    "core_svp_bits",
    "delta_from_beta",
    "estimate_sis_hardness",
]
