"""HMC strong-binding reduction (Gao et al. 2021/1674, Lemma 1 / Equation 2)."""

from __future__ import annotations

from dataclasses import dataclass
from math import log2

from .hmc import HMCKey, infinity_norm
from .ring_commitment import RingElement


class BindingReductionError(ValueError):
    """Malformed collision input or reduction failure."""


@dataclass(frozen=True)
class MSISInstance:
    """A literal M-SIS(n, m+v, q, beta) solution derived from an HMC collision."""

    z_message: tuple[RingElement, ...]
    z_randomness: tuple[RingElement, ...]
    beta: int
    relaxation: RingElement


def derive_msis_solution(
    key: HMCKey,
    relaxation: RingElement,
    message0: tuple[RingElement, ...],
    randomness0: tuple[RingElement, ...],
    message1: tuple[RingElement, ...],
    randomness1: tuple[RingElement, ...],
) -> MSISInstance:
    """Turn an HMC collision into an explicit M-SIS(n,m+v,q,beta) solution.

    Gao Lemma 1 / paper text (line 312-317): a collision
    (m0,r0) != (m1,r1) with G.(r0,m0) = G.(r1,m1) gives
    z = (m1-m0, r1-r0) solving G.z = 0 with 0 < ||z|| <= beta.
    This function builds that z literally and checks both
    conditions -- it does not merely restate the claim.
    """
    if message0 == message1 and randomness0 == randomness1:
        raise BindingReductionError("inputs are not a collision (m0,r0)=(m1,r1)")
    if len(message0) != len(message1):
        raise BindingReductionError("message width mismatch")
    if len(randomness0) != len(randomness1):
        raise BindingReductionError("randomness width mismatch")
    if any(m.params != key.params for m in (*message0, *message1)):
        raise BindingReductionError("message parameter mismatch")
    if any(r.params != key.params for r in (*randomness0, *randomness1)):
        raise BindingReductionError("randomness parameter mismatch")
    delta_m = tuple(a.sub(b) for a, b in zip(message1, message0))
    delta_r = tuple(a.sub(b) for a, b in zip(randomness1, randomness0))
    zero_check = key.commit(delta_m, delta_r)
    zero = tuple(RingElement.zero(key.params) for _ in zero_check)
    if zero_check != zero:
        raise BindingReductionError(
            "collision does not satisfy G.z=0; not a real HMC collision"
        )
    beta = infinity_norm((*delta_m, *delta_r))
    if beta <= 0:
        raise BindingReductionError("derived z has zero norm; not a valid M-SIS solution")
    return MSISInstance(
        z_message=delta_m,
        z_randomness=delta_r,
        beta=beta,
        relaxation=relaxation,
    )


@dataclass(frozen=True)
class BindingParameterCheck:
    """Equation (2): min(q, 2^(2*sqrt(n*d*log2(q)*log2(delta)))) > beta."""

    n: int
    d: int
    q: int
    delta: float
    beta: int
    lattice_bound: float
    passes: bool


def check_binding_parameters(
    n: int,
    d: int,
    q: int,
    delta: float,
    beta: int,
) -> BindingParameterCheck:
    """Evaluate Gao Equation (2) for a concrete parameter/beta/delta choice.

    This checks whether the STATED necessary condition for beta-binding
    holds; it does not itself establish hardness of the underlying M-SIS
    instance (that requires the core-SVP estimate, see lattice_estimate.py).
    """
    if n <= 0 or d <= 0 or q <= 2:
        raise BindingReductionError("n, d, q must be positive with q>2")
    if delta <= 1.0:
        raise BindingReductionError("root Hermite factor delta must exceed 1.0")
    if beta <= 0:
        raise BindingReductionError("beta must be positive")
    exponent = 2.0 * ((n * d * log2(q) * log2(delta)) ** 0.5)
    lattice_bound = min(float(q), 2.0 ** exponent)
    return BindingParameterCheck(
        n=n, d=d, q=q, delta=delta, beta=beta,
        lattice_bound=lattice_bound,
        passes=lattice_bound > beta,
    )


__all__ = [
    "BindingParameterCheck",
    "BindingReductionError",
    "MSISInstance",
    "check_binding_parameters",
    "derive_msis_solution",
]