"""Independent audit helpers for Protocol 1 rejection tuples.

The paper's two rejection shifts are not interchangeable:

* first: (x b_i)_i;
* second: x (r_e, (r_b,i)_i).

This module builds explicit coefficient tuples and reports shape/norm facts
without invoking the prover or verifier. It is a research oracle, not a proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Sequence

from .hmc import centered_coefficients
from .ring_commitment import RingElement


class RejectionAuditError(ValueError):
    """Malformed rejection-audit input."""


@dataclass(frozen=True)
class RejectionTupleAudit:
    first_response: tuple[int, ...]
    first_shift: tuple[int, ...]
    second_response: tuple[int, ...]
    second_shift: tuple[int, ...]
    first_norm: Decimal
    first_shift_norm: Decimal
    second_norm: Decimal
    second_shift_norm: Decimal
    first_dimension: int
    second_dimension: int


def _flatten(values: Sequence[Sequence[int]]) -> tuple[int, ...]:
    return tuple(value for row in values for value in row)


def _ring_flat(values: Sequence[RingElement]) -> tuple[int, ...]:
    return tuple(value for element in values for value in centered_coefficients(element))


def _l2(values: Sequence[int]) -> Decimal:
    return Decimal(sum(value * value for value in values)).sqrt()


def build_rejection_tuple_audit(
    *,
    challenge: RingElement,
    bits: Sequence[Sequence[int]],
    t: Sequence[Sequence[RingElement]],
    r_e: Sequence[RingElement],
    r_f: Sequence[RingElement],
    openings: Sequence[Sequence[RingElement]],
    r_t: Sequence[Sequence[RingElement]],
    responses_g: Sequence[Sequence[RingElement]],
    response_zg: Sequence[RingElement],
    response_zb_by_index: Sequence[Sequence[RingElement]],
) -> RejectionTupleAudit:
    """Construct the exact paper-shaped first/second rejection tuples.

    The second response is kept per-index before any zeta aggregation. This is
    required because Gao Step 10 rejects ``(z_g,(z_b,i)_i)`` against
    ``x(r_e,(r_b,i)_i)``; using only the aggregated ``z_b`` changes the law.
    """
    count = len(bits)
    if count == 0 or len(t) != count or len(openings) != count or len(r_t) != count:
        raise RejectionAuditError("vector counts differ")
    width = len(bits[0])
    if width == 0 or any(len(row) != width for row in bits):
        raise RejectionAuditError("bit dimensions differ")
    if any(len(row) != width for row in t):
        raise RejectionAuditError("t dimensions differ")
    if len(responses_g) != count or any(len(row) != width for row in responses_g):
        raise RejectionAuditError("g response dimensions differ")
    if len(response_zb_by_index) != count:
        raise RejectionAuditError("per-index z_b response dimensions differ")
    randomness_width = len(r_e)
    if randomness_width == 0 or len(r_f) != randomness_width or len(response_zg) != randomness_width:
        raise RejectionAuditError("opening dimensions differ")
    if any(len(row) != randomness_width for row in openings):
        raise RejectionAuditError("opening width differs")
    if any(len(row) != randomness_width for row in r_t):
        raise RejectionAuditError("r_t width differs")
    if any(len(row) != randomness_width for row in response_zb_by_index):
        raise RejectionAuditError("per-index z_b width differs")
    params = challenge.params
    all_values = [challenge, *r_e, *r_f, *response_zg]
    all_values.extend(value for row in t for value in row)
    all_values.extend(value for row in openings for value in row)
    all_values.extend(value for row in r_t for value in row)
    all_values.extend(value for row in responses_g for value in row)
    all_values.extend(value for row in response_zb_by_index for value in row)
    if any(value.params != params for value in all_values):
        raise RejectionAuditError("ring parameter mismatch")
    challenge_coefficients = centered_coefficients(challenge)
    zero_ring = (0,) * params.n
    first_shift = tuple(
        coefficient
        for row in bits
        for bit in row
        for coefficient in (challenge_coefficients if bit else zero_ring)
    )
    first_response = tuple(
        coefficient
        for row in responses_g
        for value in row
        for coefficient in centered_coefficients(value)
    )
    if len(first_response) != len(first_shift):
        raise RejectionAuditError("first tuple dimensions differ")
    second_shift = _ring_flat((
        *r_e,
        *(value for row in openings for value in row),
    ))
    # The response tuple is (z_g,(z_b,i)_i), before zeta aggregation.
    second_response = _ring_flat((
        *response_zg,
        *(value for row in response_zb_by_index for value in row),
    ))
    if len(second_response) != len(second_shift):
        raise RejectionAuditError("second tuple dimensions differ")
    # The shift is x times each component; the independent coefficient oracle
    # cannot replace ring multiplication with coordinatewise multiplication.
    def ringwise_product(values: Sequence[RingElement]) -> tuple[int, ...]:
        output = []
        for value in values:
            product = challenge.mul(value)
            output.extend(centered_coefficients(product))
        return tuple(output)
    second_shift = ringwise_product((
        *r_e,
        *(value for row in openings for value in row),
    ))
    return RejectionTupleAudit(
        first_response, first_shift, second_response, second_shift,
        _l2(first_response), _l2(first_shift),
        _l2(second_response), _l2(second_shift),
        len(first_response), len(second_response),
    )


__all__ = ["RejectionAuditError", "RejectionTupleAudit", "build_rejection_tuple_audit"]
