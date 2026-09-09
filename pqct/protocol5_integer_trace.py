"""Unreduced integer trace for Protocol 5 (conservation), the missing half.

`pqct/protocol1_integer_trace.py` audits Protocol 1's expressions over
Z[X]/(X^d+1) instead of R_q. Protocol 5 had NO equivalent, which is the more
dangerous omission: Protocol 5's entire soundness argument is that
conservation must hold over the INTEGERS, not merely mod q. A cheating
prover whose weighted sum equals a nonzero multiple of q satisfies every
R_q equation while creating value out of nothing.

The verifier already has one gate for this (`f0_in_canonical_range`, which
lifts f_0 over Z and rejects out-of-range results). This module audits the
rest of the chain, so a wraparound anywhere else cannot hide:

  * the cycle-mask telescoping identity  sum_j 2^j d_j == 0
  * the response  f_j = x*c_j + d_j
  * the f_0 reconstruction  f_0 = -sum_{j>=1} 2^j f_j
  * the weighted column sum  sum_j 2^j c_j
  * the randomness aggregation  r_c = sum_i lambda_i r_{b,i}
  * the z response  z = x*r_c + r_d

For each it records the unreduced integer value, the R_q value, whether they
AGREE after canonical reduction, and whether the integer value stayed inside
the centered mod-q window. "Agrees but overflowed" is the interesting case:
it means the R_q check passed while the integer statement was false, which
is exactly the cheat Protocol 5 exists to stop.

HONEST SCOPE: an audit instrument. `safe` means every RECORDED expression
stayed in range and matched; it is not a soundness proof and says nothing
about unrecorded operations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from .hmc import centered_coefficients
from .ring_commitment import RingElement


class Protocol5TraceError(ValueError):
    """Malformed Protocol 5 trace input."""


Poly = tuple


def _center(value: RingElement) -> Poly:
    return centered_coefficients(value)


def _zero(n: int) -> Poly:
    return (0,) * n


def _add(left: Sequence[int], right: Sequence[int]) -> Poly:
    if len(left) != len(right):
        raise Protocol5TraceError("integer polynomial widths differ")
    return tuple(a + b for a, b in zip(left, right))


def _sub(left: Sequence[int], right: Sequence[int]) -> Poly:
    if len(left) != len(right):
        raise Protocol5TraceError("integer polynomial widths differ")
    return tuple(a - b for a, b in zip(left, right))


def _scale(values: Sequence[int], scalar: int) -> Poly:
    return tuple(scalar * value for value in values)


def _mul(left: Sequence[int], right: Sequence[int]) -> Poly:
    """Negacyclic product over Z: X^n = -1, NO modular reduction."""
    n = len(left)
    if len(right) != n:
        raise Protocol5TraceError("integer polynomial widths differ")
    out = [0] * n
    for i, a in enumerate(left):
        if a == 0:
            continue
        for j, b in enumerate(right):
            if b == 0:
                continue
            index = i + j
            if index < n:
                out[index] += a * b
            else:
                out[index - n] -= a * b
    return tuple(out)


def _canonical(values: Sequence[int], q: int) -> Poly:
    return tuple(value % q for value in values)


def _in_centered_window(values: Sequence[int], q: int) -> bool:
    """True when every coefficient fits the centered interval for q.

    Outside it, reduction mod q changes the value, so an R_q identity can
    hold while the integer identity does not.
    """
    half = q // 2
    return all(-half <= value <= half for value in values)


@dataclass(frozen=True)
class Observation:
    """One recorded expression: integer value vs R_q value."""

    name: str
    integer_value: Poly
    ring_value: Poly
    q: int

    @property
    def agrees_mod_q(self) -> bool:
        return _canonical(self.integer_value, self.q) == _canonical(
            self.ring_value, self.q
        )

    @property
    def in_window(self) -> bool:
        return _in_centered_window(self.integer_value, self.q)

    @property
    def overflowed(self) -> bool:
        """Integer value left the window: mod-q agreement is then NOT
        evidence that the integer statement holds."""
        return not self.in_window

    @property
    def max_abs(self) -> int:
        return max((abs(v) for v in self.integer_value), default=0)

    def summary(self) -> dict:
        return {
            "name": self.name,
            "agrees_mod_q": self.agrees_mod_q,
            "in_window": self.in_window,
            "overflowed": self.overflowed,
            "max_abs": self.max_abs,
            "q_half": self.q // 2,
        }


@dataclass
class Protocol5TraceReport:
    """All recorded observations plus a single verdict."""

    q: int
    observations: list = field(default_factory=list)

    def record(self, name: str, integer_value, ring_value) -> Observation:
        observation = Observation(
            name=name,
            integer_value=tuple(integer_value),
            ring_value=tuple(ring_value),
            q=self.q,
        )
        self.observations.append(observation)
        return observation

    @property
    def all_agree(self) -> bool:
        return all(o.agrees_mod_q for o in self.observations)

    @property
    def any_overflow(self) -> bool:
        return any(o.overflowed for o in self.observations)

    @property
    def safe(self) -> bool:
        """Every recorded expression matched R_q AND stayed in range."""
        return bool(self.observations) and self.all_agree and not self.any_overflow

    @property
    def overflowed_names(self) -> tuple:
        return tuple(o.name for o in self.observations if o.overflowed)

    @property
    def disagreeing_names(self) -> tuple:
        return tuple(o.name for o in self.observations if not o.agrees_mod_q)

    def summary(self) -> dict:
        return {
            "q": self.q,
            "recorded": len(self.observations),
            "all_agree_mod_q": self.all_agree,
            "any_overflow": self.any_overflow,
            "safe": self.safe,
            "overflowed": list(self.overflowed_names),
            "disagreeing": list(self.disagreeing_names),
            "observations": [o.summary() for o in self.observations],
        }


def trace_cycle_mask(mask: Sequence[RingElement], q: int) -> Observation:
    """sum_j 2^j d_j must be EXACTLY zero over Z, not just mod q.

    This is the telescoping identity that makes f_0 recoverable. If it only
    held mod q, the verifier's integer reconstruction would be meaningless.
    """
    if not mask:
        raise Protocol5TraceError("mask must not be empty")
    n = len(mask[0].coeffs)
    total = _zero(n)
    for index, element in enumerate(mask):
        total = _add(total, _scale(_center(element), 1 << index))
    report = Protocol5TraceReport(q=q)
    return report.record("cycle_mask_weighted_sum", total, _zero(n))


def trace_protocol5(
    *,
    q: int,
    challenge: RingElement,
    columns: Sequence[int],
    mask: Sequence[RingElement],
    response_tail: Sequence[RingElement],
    openings: Sequence[Sequence[RingElement]],
    lambdas: Sequence[int],
    mask_randomness: Sequence[RingElement],
    response_z: Sequence[RingElement],
) -> Protocol5TraceReport:
    """Audit every Protocol 5 expression over Z alongside its R_q value.

    `columns` are the integer balance columns c_j (scalars, embedded as
    constant polynomials). Everything else is a ring element from the real
    transcript.
    """
    if not mask or not response_tail:
        raise Protocol5TraceError("mask and response tail must not be empty")
    n = len(mask[0].coeffs)
    report = Protocol5TraceReport(q=q)
    x_int = _center(challenge)

    # 1. Cycle mask telescoping: sum_j 2^j d_j == 0 over Z.
    total = _zero(n)
    for index, element in enumerate(mask):
        total = _add(total, _scale(_center(element), 1 << index))
    report.record("cycle_mask_weighted_sum", total, _zero(n))

    # 2. Weighted column sum: sum_j 2^j c_j == 0 over Z for a conserving tx.
    column_sum = 0
    for index, value in enumerate(columns):
        column_sum += (1 << index) * int(value)
    report.record(
        "column_weighted_sum",
        (column_sum,) + (0,) * (n - 1),
        _zero(n),
    )

    # 3. Responses f_j = x*c_j + d_j for j >= 1 (the transmitted tail).
    for index, element in enumerate(response_tail, start=1):
        if index >= len(columns) or index >= len(mask):
            break
        c_poly = (int(columns[index]),) + (0,) * (n - 1)
        expected = _add(_mul(x_int, c_poly), _center(mask[index]))
        report.record(f"response_f{index}", expected, _center(element))

    # 4. f_0 reconstruction: f_0 = -sum_{j>=1} 2^j f_j over Z.
    reconstructed = _zero(n)
    for offset, element in enumerate(response_tail):
        power = 1 << (offset + 1)
        reconstructed = _sub(reconstructed, _scale(_center(element), power))
    c0_poly = (int(columns[0]),) + (0,) * (n - 1) if columns else _zero(n)
    expected_f0 = _add(_mul(x_int, c0_poly), _center(mask[0]))
    report.record("f0_reconstruction", reconstructed, expected_f0)

    # 5. Randomness aggregation r_c = sum_i lambda_i r_{b,i} over Z.
    if openings:
        width = len(openings[0])
        for position in range(width):
            aggregate = _zero(n)
            for lam, opening in zip(lambdas, openings):
                aggregate = _add(
                    aggregate, _scale(_center(opening[position]), int(lam))
                )
            # 6. z = x*r_c + r_d for this position.
            if position < len(mask_randomness) and position < len(response_z):
                expected_z = _add(
                    _mul(x_int, aggregate), _center(mask_randomness[position])
                )
                report.record(
                    f"response_z{position}",
                    expected_z,
                    _center(response_z[position]),
                )
    return report


__all__ = [
    "Observation",
    "Protocol5TraceError",
    "Protocol5TraceReport",
    "trace_cycle_mask",
    "trace_protocol5",
]
