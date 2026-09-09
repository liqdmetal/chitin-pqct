"""Gao Protocol 5 (body: Protocol 2) linear-equation transcript, ring level.

Implements the cycle-masked conservation proof machinery over ring
elements: D = Com(d; r_d), challenge x, response f_1 = x*c_1 + d_1
(f_0 omitted), verifier recomputes f_0 = -sum_{j>=1} 2^j f_j OVER R
and rejects unless f_0 lies in R_q (no overflow). Research oracle;
rejection sampling and full Protocol 1 composition are NOT included.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .cycle_masking import CycleMask, derive_cycle_mask
from .hmc import HMCError, HMCKey, centered_coefficients
from .ring_commitment import EncodingError, RingElement


class LinearEquationError(ValueError):
    """Malformed linear-equation transcript input."""


@dataclass(frozen=True)
class CycleMaskCommitment:
    """D = Com((d_j); r_d) with the cycle-mask identity <d,2^k>=0."""

    mask: CycleMask
    randomness: tuple[RingElement, ...]
    commitment: tuple[RingElement, ...]


def build_cycle_mask_commitment(
    key: HMCKey,
    sampled_mask: Sequence[int],
    randomness: Sequence[RingElement],
) -> CycleMaskCommitment:
    """Derive the cycle mask and commit to its coefficients.

    d_j = d~_j - 2*d~_{j+1} with d~_0 = d~_k = 0 guarantees
    sum_j 2^j d_j = 0 exactly over the integers (Gao eq.16), which is
    what lets the prover omit f_0 and dsum from the transcript.
    """
    try:
        mask = derive_cycle_mask(sampled_mask)
    except (TypeError, ValueError) as error:
        raise LinearEquationError(str(error)) from error
    if key.message_width != len(mask.values):
        raise LinearEquationError(
            "HMC message width must equal the cycle-mask length k"
        )
    randomness_tuple = tuple(randomness)
    if len(randomness_tuple) != key.randomness_width:
        raise LinearEquationError("randomness width mismatch")
    if any(value.params != key.params for value in randomness_tuple):
        raise LinearEquationError("randomness parameter mismatch")
    params = key.params
    mask_elements = tuple(
        RingElement.from_coeffs((value,) + (0,) * (params.n - 1), params)
        for value in mask.values
    )
    try:
        commitment = key.commit(mask_elements, randomness_tuple)
    except (HMCError, TypeError, ValueError) as error:
        raise LinearEquationError(f"cycle-mask commitment failed: {error}") from error
    return CycleMaskCommitment(mask, randomness_tuple, commitment)


def _constant_poly(value: int, params) -> RingElement:
    return RingElement.from_coeffs((value,) + (0,) * (params.n - 1), params)


def compute_response_tail(
    challenge: RingElement,
    columns: Sequence[int],
    mask: CycleMask,
) -> tuple[RingElement, ...]:
    """Prover step 11: f_j = x*c_j + d_j for j in [1, k).

    f_0 is deliberately OMITTED (Gao step 10/16): the cycle mask makes
    <d,2^k> = 0, so f_0 is recoverable by the verifier from the tail.
    """
    if len(columns) != len(mask.values):
        raise LinearEquationError("column/mask length mismatch")
    if len(columns) < 2:
        raise LinearEquationError("cycle mask needs at least two coordinates")
    params = challenge.params
    tail = []
    for index in range(1, len(columns)):
        f_j = challenge.mul(_constant_poly(columns[index], params)).add(
            _constant_poly(mask.values[index], params)
        )
        tail.append(f_j)
    return tuple(tail)


def reconstruct_f0_over_integers(
    response_tail: Sequence[RingElement],
) -> tuple[int, ...]:
    """Verifier step 16: f_0 = -sum_{j>=1} 2^j * f_j computed OVER Z.

    This is integer polynomial arithmetic on centered coefficients with
    NO modular reduction -- exactly the "run on R instead of R_q" the
    paper requires to expose overflow (a cheating c with sum 2^j c_j a
    nonzero multiple of q passes the R_q commitment equation but makes
    the reconstructed f_0 fall outside the canonical range).
    """
    if not response_tail:
        raise LinearEquationError("response tail cannot be empty")
    params = response_tail[0].params
    if any(value.params != params for value in response_tail):
        raise LinearEquationError("response parameter mismatch")
    n = params.n
    total = [0] * n
    for offset, element in enumerate(response_tail):
        power = 1 << (offset + 1)
        for index, coefficient in enumerate(centered_coefficients(element)):
            total[index] -= power * coefficient
    return tuple(total)


def f0_in_canonical_range(f0_integers: Sequence[int], q: int) -> bool:
    """Check the reconstructed integer f_0 fits R_q's centered range.

    Gao step 17's `f_0 in R_q` gate: |coefficient| must stay strictly
    inside the centered interval, otherwise the transcript is rejected.
    """
    if q <= 2:
        raise LinearEquationError("modulus must exceed 2")
    half = q // 2
    return all(-half < value <= half for value in f0_integers)


def check_commitment_equation(
    key: HMCKey,
    challenge: RingElement,
    c_commitment: Sequence[RingElement],
    mask_commitment: Sequence[RingElement],
    f0_element: RingElement,
    response_tail: Sequence[RingElement],
    z_randomness: Sequence[RingElement],
) -> bool:
    """Gao step 17: x*C + D == Com((f_0, f_1..f_{k-1}); z) in R_q.

    C is the verifier-computed commitment to c (eq.11 combination),
    D the cycle-mask commitment, z = x*r_c + r_d the response opening.
    """
    try:
        if len(c_commitment) != key.ring_rows or len(mask_commitment) != key.ring_rows:
            return False
        if len(z_randomness) != key.randomness_width:
            return False
        lhs = tuple(
            challenge.mul(c_row).add(d_row)
            for c_row, d_row in zip(c_commitment, mask_commitment)
        )
        f_vector = (f0_element, *tuple(response_tail))
        if len(f_vector) != key.message_width:
            return False
        rhs = key.commit(f_vector, tuple(z_randomness))
        return lhs == rhs
    except (HMCError, EncodingError, TypeError, ValueError):
        return False


__all__ = [
    "CycleMaskCommitment",
    "LinearEquationError",
    "build_cycle_mask_commitment",
    "check_commitment_equation",
    "compute_response_tail",
    "f0_in_canonical_range",
    "reconstruct_f0_over_integers",
]


