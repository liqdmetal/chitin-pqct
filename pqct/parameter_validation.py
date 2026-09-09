"""Paper-grounded parameter validation: relation bound -> hardness estimate.

Composes the paper-transcribed bound formulas (pqct.paper_bounds) with the
core-SVP hardness estimator (pqct.lattice_estimate) into one chain:

  Protocol parameters
    -> required HMC binding bound (gamma_bin / gamma_LE, Theorem 1/2)
    -> Theorem 1 q/2 precondition check
    -> feed the binding bound as the M-SIS beta into Gao Eq.(2)
    -> required root-Hermite factor delta
    -> BKZ blocksize -> core-SVP bit estimates

This answers "do these parameters deliver the claimed security level?" for
a CONCRETE parameter set. It does not certify anything: the hardness
estimator is the self-built cited-constants approximation, not the verified
Albrecht/Player/Scott lattice-estimator (unavailable without Sage).
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from .lattice_estimate import LatticeEstimateError, estimate_sis_hardness
from .paper_bounds import (
    PaperBoundsError,
    gamma_bin,
    gamma_le,
    protocol1_q_precondition_holds,
)


class ParameterValidationError(ValueError):
    """Invalid parameter-validation input."""


@dataclass(frozen=True)
class Protocol1Validation:
    """Theorem 1 precondition + binding-bound hardness for Protocol 1."""

    q_precondition_holds: bool
    gamma_bin_required: Decimal
    hardness: object
    note: str


@dataclass(frozen=True)
class Protocol5Validation:
    """Theorem 2 binding-bound hardness for Protocol 5."""

    gamma_le_required: Decimal
    hardness: object
    note: str


def _to_sis_beta(gamma: Decimal) -> int:
    """Convert a real-valued binding bound to the integer beta the estimator wants.

    The bound is a norm ceiling; round UP so the hardness estimate is not
    optimistic about the adversary's allowed solution size.
    """
    if gamma <= 0:
        raise ParameterValidationError("binding bound must be positive")
    beta = int(gamma.to_integral_value(rounding="ROUND_CEILING"))
    return max(1, beta)


def validate_protocol1_parameters(
    *, q: int, n: int, d: int, w: int, p: int, k: int,
    phi1: Decimal, phi2: Decimal, B: int, m: int,
) -> Protocol1Validation:
    """Run Theorem 1's precondition and binding-bound hardness estimate."""
    if min(n, d, w, p, k, B, m) <= 0 or q <= 2:
        raise ParameterValidationError("all dimensions positive and q>2 required")
    try:
        holds = protocol1_q_precondition_holds(q, w, phi1, p, k, d)
        gb = gamma_bin(p, d, w, k, phi1, phi2, B, m)
    except PaperBoundsError as error:
        raise ParameterValidationError(str(error)) from error

    beta = _to_sis_beta(gb)
    note = "precondition OK" if holds else (
        "q/2 <= 16*(w*phi1)^2*p*k*d -- Theorem 1 precondition FAILS; "
        "soundness theorem does not apply to these parameters"
    )
    try:
        hardness = estimate_sis_hardness(n=n, d=d, q=q, beta_bound=beta)
    except LatticeEstimateError as error:
        return Protocol1Validation(holds, gb, None, note + f"; hardness: {error}")
    return Protocol1Validation(holds, gb, hardness, note)


def validate_protocol5_parameters(
    *, q: int, n: int, d: int, w: int, p: int,
    phi3: Decimal, B: int, m: int, omega_l1: int, account_count: int,
) -> Protocol5Validation:
    """Run Theorem 2's binding-bound hardness estimate."""
    if min(n, d, w, p, B, m, omega_l1) <= 0 or account_count < 1 or q <= 2:
        raise ParameterValidationError("invalid Protocol 5 dimensions")
    try:
        gle = gamma_le(phi3, m, d, B, w, p, omega_l1, account_count)
    except PaperBoundsError as error:
        raise ParameterValidationError(str(error)) from error

    beta = _to_sis_beta(gle)
    try:
        hardness = estimate_sis_hardness(n=n, d=d, q=q, beta_bound=beta)
    except LatticeEstimateError as error:
        return Protocol5Validation(gle, None, f"hardness: {error}")
    return Protocol5Validation(gle, hardness, "binding-bound hardness estimated")


__all__ = [
    "ParameterValidationError",
    "Protocol1Validation",
    "Protocol5Validation",
    "validate_protocol1_parameters",
    "validate_protocol5_parameters",
]
