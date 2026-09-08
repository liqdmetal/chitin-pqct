"""Unreduced integer trace for Gao Protocol 1 equation experiments.

The normal verifier works in R_q and therefore cannot tell whether a bounded
integer relation was reduced modulo q before it was checked. This module keeps
a parallel Z[X]/(X^d+1) trace for the witness-response, quadratic, challenge-
power, aggregation, and pairwise-extraction expressions.

It is an audit instrument, not a security proof. ``safe`` means that every
expression recorded by this module stayed coefficient-wise inside the centered
mod-q interval and agreed with its supplied R_q expression. It does not claim
that unrecorded operations are safe, nor that the protocol is sound.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .binary_protocol1_ring import RingProtocol1Proof
from .hmc import centered_coefficients
from .ring_commitment import RingElement

Poly = tuple[int, ...]


class IntegerTraceError(ValueError):
    """Malformed trace input."""


def _center(value: RingElement) -> Poly:
    return centered_coefficients(value)


def _zero(n: int) -> Poly:
    return (0,) * n


def _one(n: int) -> Poly:
    return (1,) + (0,) * (n - 1)


def _add(left: Sequence[int], right: Sequence[int]) -> Poly:
    if len(left) != len(right):
        raise IntegerTraceError("integer polynomial widths differ")
    return tuple(a + b for a, b in zip(left, right))


def _sub(left: Sequence[int], right: Sequence[int]) -> Poly:
    if len(left) != len(right):
        raise IntegerTraceError("integer polynomial widths differ")
    return tuple(a - b for a, b in zip(left, right))


def _mul(left: Sequence[int], right: Sequence[int]) -> Poly:
    if len(left) != len(right) or not left:
        raise IntegerTraceError("integer polynomial widths differ")
    n = len(left)
    result = [0] * n
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            degree = i + j
            if degree < n:
                result[degree] += a * b
            else:
                result[degree - n] -= a * b
    return tuple(result)


def _canonical(value: Sequence[int], q: int) -> Poly:
    return tuple(int(coefficient) % q for coefficient in value)


def _flatten(rows: Sequence[Sequence[Poly]]) -> tuple[Poly, ...]:
    return tuple(value for row in rows for value in row)


def _ring_zero(params) -> RingElement:
    return RingElement.zero(params)


def _ring_one(params) -> RingElement:
    return RingElement.from_coeffs(_one(params.n), params)


def _weighted_raw(rows: Sequence[Sequence[Poly]], zeta: Poly) -> tuple[Poly, ...]:
    if not rows or not rows[0]:
        raise IntegerTraceError("cannot aggregate empty rows")
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise IntegerTraceError("aggregate row widths differ")
    total = [_zero(len(zeta)) for _ in range(width)]
    power = _one(len(zeta))
    for row in rows:
        for index, value in enumerate(row):
            total[index] = _add(total[index], _mul(power, value))
        power = _mul(power, zeta)
    return tuple(total)


def _weighted_ring(rows: Sequence[Sequence[RingElement]], zeta: RingElement) -> tuple[RingElement, ...]:
    if not rows or not rows[0]:
        raise IntegerTraceError("cannot aggregate empty ring rows")
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise IntegerTraceError("aggregate ring row widths differ")
    total = [_ring_zero(zeta.params) for _ in range(width)]
    power = _ring_one(zeta.params)
    for row in rows:
        for index, value in enumerate(row):
            total[index] = total[index].add(power.mul(value))
        power = power.mul(zeta)
    return tuple(total)


@dataclass(frozen=True)
class IntegerTraceObservation:
    """One unreduced integer expression and its optional R_q counterpart."""

    label: str
    raw: Poly
    actual: Poly | None
    max_abs: int
    within_centered_modulus: bool
    matches_actual: bool | None

    @property
    def safe(self) -> bool:
        return self.within_centered_modulus and self.matches_actual is not False


@dataclass(frozen=True)
class IntegerTraceReport:
    """Trace result for one transcript or extracted pair."""

    modulus: int
    observations: tuple[IntegerTraceObservation, ...]
    violations: tuple[str, ...]

    @property
    def safe(self) -> bool:
        return not self.violations

    @property
    def max_abs(self) -> int:
        return max((observation.max_abs for observation in self.observations), default=0)

    @property
    def checked_values(self) -> int:
        return sum(len(observation.raw) for observation in self.observations)


@dataclass(frozen=True)
class PairIntegerTrace:
    """Two transcript traces plus the extracted pairwise-expression trace."""

    first: IntegerTraceReport
    second: IntegerTraceReport
    pair: IntegerTraceReport

    @property
    def safe(self) -> bool:
        return self.first.safe and self.second.safe and self.pair.safe

    @property
    def checked_values(self) -> int:
        return self.first.checked_values + self.second.checked_values + self.pair.checked_values


def _TraceBuilder(q: int) -> "_TraceState":
    if q <= 2:
        raise IntegerTraceError("modulus must be greater than two")
    return _TraceState(q)


class _TraceState:
    def __init__(self, q: int) -> None:
        self.q = q
        self.items: list[IntegerTraceObservation] = []
        self.violations: list[str] = []

    def record(self, label: str, raw: Sequence[int], actual: RingElement | None = None) -> None:
        values = tuple(int(value) for value in raw)
        if actual is not None and len(values) != len(actual.coeffs):
            raise IntegerTraceError(f"{label}: actual polynomial width differs")
        maximum = max((abs(value) for value in values), default=0)
        within = all(2 * abs(value) < self.q for value in values)
        actual_coefficients = tuple(actual.coeffs) if actual is not None else None
        matches = None if actual is None else _canonical(values, self.q) == actual_coefficients
        self.items.append(IntegerTraceObservation(label, values, actual_coefficients, maximum, within, matches))
        if not within:
            self.violations.append(f"{label}: coefficient reaches or crosses q/2")
        if matches is False:
            self.violations.append(f"{label}: integer expression disagrees after canonical reduction")

    def finish(self) -> IntegerTraceReport:
        return IntegerTraceReport(self.q, tuple(self.items), tuple(self.violations))


def _validate_transcript_shapes(
    proof: RingProtocol1Proof,
    x: RingElement,
    zeta: RingElement,
    bits: Sequence[Sequence[RingElement]],
    openings: Sequence[Sequence[RingElement]],
    masks_t: Sequence[Sequence[RingElement]],
    mask_opening_e: Sequence[RingElement],
    mask_opening_f: Sequence[RingElement],
    mask_openings_t: Sequence[Sequence[RingElement]],
) -> tuple[int, int]:
    count = len(bits)
    if count == 0 or len(openings) != count or len(masks_t) != count or len(mask_openings_t) != count:
        raise IntegerTraceError("transcript row dimensions differ")
    width = len(bits[0])
    if width == 0 or any(len(row) != width for row in bits):
        raise IntegerTraceError("transcript bit widths differ")
    if any(len(row) != width for row in masks_t):
        raise IntegerTraceError("transcript mask widths differ")
    if len(proof.responses_g) != count or any(len(row) != width for row in proof.responses_g):
        raise IntegerTraceError("proof response dimensions differ")
    if any(len(row) != len(openings[index]) for index, row in enumerate(mask_openings_t)):
        raise IntegerTraceError("opening and r_t row widths differ")
    if any(len(row) != len(openings[0]) for row in openings):
        raise IntegerTraceError("opening randomness widths differ")
    if len(mask_opening_e) != len(mask_opening_f) or len(mask_opening_e) != len(proof.response_zg):
        raise IntegerTraceError("z_g opening dimensions differ")
    if len(proof.response_zb) != len(mask_openings_t[0]) or len(proof.response_zb) != len(openings[0]):
        raise IntegerTraceError("z_b opening dimensions differ")
    for collection in (bits, openings, masks_t, mask_openings_t, (mask_opening_e, mask_opening_f)):
        for row in collection:
            for value in row:
                if value.params != x.params:
                    raise IntegerTraceError("transcript parameter mismatch")
    if any(value.params != x.params for value in (*proof.response_zg, *proof.response_zb)):
        raise IntegerTraceError("proof response parameter mismatch")
    if zeta.params != x.params:
        raise IntegerTraceError("challenge parameter mismatch")
    return count, width


def trace_protocol1_response(
    proof: RingProtocol1Proof,
    x: RingElement,
    zeta: RingElement,
    bits: Sequence[Sequence[RingElement]],
    openings: Sequence[Sequence[RingElement]],
    masks_t: Sequence[Sequence[RingElement]],
    mask_opening_e: Sequence[RingElement],
    mask_opening_f: Sequence[RingElement],
    mask_openings_t: Sequence[Sequence[RingElement]],
) -> IntegerTraceReport:
    """Trace one transcript's response, quadratic, and aggregate expressions."""
    count, width = _validate_transcript_shapes(
        proof, x, zeta, bits, openings, masks_t,
        mask_opening_e, mask_opening_f, mask_openings_t,
    )
    state = _TraceBuilder(x.params.q)
    x_raw = _center(x)
    zeta_raw = _center(zeta)
    raw_power = _one(x.params.n)
    ring_power = _ring_one(x.params)
    for index in range(count):
        state.record(f"zeta_power[{index}]", raw_power, ring_power)
        raw_power = _mul(raw_power, zeta_raw)
        ring_power = ring_power.mul(zeta)

    raw_g_rows: list[tuple[Poly, ...]] = []
    raw_h_rows: list[tuple[Poly, ...]] = []
    raw_zb_rows: list[tuple[Poly, ...]] = []
    for row_index in range(count):
        raw_g_row: list[Poly] = []
        raw_h_row: list[Poly] = []
        for column in range(width):
            bit_raw = _center(bits[row_index][column])
            mask_raw = _center(masks_t[row_index][column])
            response = proof.responses_g[row_index][column]
            g_raw = _add(_mul(x_raw, bit_raw), mask_raw)
            state.record(f"g[{row_index}][{column}]", g_raw, response)
            h_raw = _mul(g_raw, _sub(x_raw, g_raw))
            h_actual = response.mul(x.sub(response))
            state.record(f"h[{row_index}][{column}]", h_raw, h_actual)
            state.record(f"x_h[{row_index}][{column}]", _mul(x_raw, h_raw), x.mul(h_actual))
            raw_g_row.append(g_raw)
            raw_h_row.append(h_raw)
        raw_zb_row: list[Poly] = []
        for coordinate, (opening_value, r_t_value) in enumerate(zip(openings[row_index], mask_openings_t[row_index])):
            opening_raw = _center(opening_value)
            r_t_raw = _center(r_t_value)
            zbi_raw = _add(_mul(x_raw, opening_raw), r_t_raw)
            zbi_actual = x.mul(opening_value).add(r_t_value)
            state.record(f"z_b_row[{row_index}][{coordinate}]", zbi_raw, zbi_actual)
            raw_zb_row.append(zbi_raw)
        raw_g_rows.append(tuple(raw_g_row))
        raw_h_rows.append(tuple(raw_h_row))
        raw_zb_rows.append(tuple(raw_zb_row))

    raw_zg: list[Poly] = []
    for index, (re_value, rf_value, response) in enumerate(zip(mask_opening_e, mask_opening_f, proof.response_zg)):
        zg_raw = _add(_mul(x_raw, _center(re_value)), _center(rf_value))
        zg_actual = x.mul(re_value).add(rf_value)
        state.record(f"z_g[{index}]", zg_raw, response)
        state.record(f"x_z_g[{index}]", _mul(x_raw, zg_raw), x.mul(zg_actual))
        raw_zg.append(zg_raw)

    raw_weighted_g = _weighted_raw(raw_g_rows, zeta_raw)
    actual_weighted_g = _weighted_ring(proof.responses_g, zeta)
    for index, (raw_value, actual_value) in enumerate(zip(raw_weighted_g, actual_weighted_g)):
        state.record(f"weighted_g[{index}]", raw_value, actual_value)
    raw_zb = _weighted_raw(raw_zb_rows, zeta_raw)
    for index, (raw_value, actual_value) in enumerate(zip(raw_zb, proof.response_zb)):
        state.record(f"z_b[{index}]", raw_value, actual_value)
    return state.finish()


def _validate_pair_shape(
    first: RingProtocol1Proof,
    second: RingProtocol1Proof,
    x_first: RingElement,
    x_second: RingElement,
    zeta: RingElement,
) -> None:
    if x_first.params != x_second.params or x_first.params != zeta.params:
        raise IntegerTraceError("pair challenge parameter mismatch")
    if len(first.responses_g) != len(second.responses_g):
        raise IntegerTraceError("pair response row dimensions differ")
    if any(len(a) != len(b) for a, b in zip(first.responses_g, second.responses_g)):
        raise IntegerTraceError("pair response widths differ")
    if len(first.response_zg) != len(second.response_zg) or len(first.response_zb) != len(second.response_zb):
        raise IntegerTraceError("pair opening response dimensions differ")
    for values in (*first.responses_g, *second.responses_g, first.response_zg, second.response_zg, first.response_zb, second.response_zb):
        if any(value.params != x_first.params for value in values):
            raise IntegerTraceError("pair response parameter mismatch")


def trace_protocol1_pair(
    first: RingProtocol1Proof,
    second: RingProtocol1Proof,
    x_first: RingElement,
    x_second: RingElement,
    zeta: RingElement,
    *,
    first_inputs: tuple[Sequence[Sequence[RingElement]], Sequence[Sequence[RingElement]], Sequence[Sequence[RingElement]], Sequence[RingElement], Sequence[RingElement], Sequence[Sequence[RingElement]]] | None = None,
) -> PairIntegerTrace:
    """Trace two responses and the raw equations used by second-layer extraction.

    Complete pair tracing requires the witness/mask inputs. Without them there
    is no honest expected value for the response equations, so the function
    rejects that incomplete mode instead of returning a false-green report.
    """
    _validate_pair_shape(first, second, x_first, x_second, zeta)
    if first_inputs is None:
        raise IntegerTraceError("complete pair tracing requires first_inputs")
    bits, openings, masks_t, re, rf, rt = first_inputs
    first_report = trace_protocol1_response(first, x_first, zeta, bits, openings, masks_t, re, rf, rt)
    second_report = trace_protocol1_response(second, x_second, zeta, bits, openings, masks_t, re, rf, rt)

    state = _TraceBuilder(x_first.params.q)
    x0 = _center(x_first)
    x1 = _center(x_second)
    zeta_raw = _center(zeta)
    state.record("pair.y", _sub(x0, x1), x_first.sub(x_second))
    g0_raw = tuple(tuple(_center(value) for value in row) for row in first.responses_g)
    g1_raw = tuple(tuple(_center(value) for value in row) for row in second.responses_g)
    m0_raw = _weighted_raw(g0_raw, zeta_raw)
    m1_raw = _weighted_raw(g1_raw, zeta_raw)
    m0_ring = _weighted_ring(first.responses_g, zeta)
    m1_ring = _weighted_ring(second.responses_g, zeta)
    for index, (raw_value, actual_value) in enumerate(zip(m0_raw, m0_ring)):
        state.record(f"pair.M0[{index}]", raw_value, actual_value)
    for index, (raw_value, actual_value) in enumerate(zip(m1_raw, m1_ring)):
        state.record(f"pair.M1[{index}]", raw_value, actual_value)
    for index, (raw0, raw1, actual0, actual1) in enumerate(zip(m0_raw, m1_raw, m0_ring, m1_ring)):
        state.record(f"pair.delta_b[{index}]", _sub(raw0, raw1), actual0.sub(actual1))
        state.record(f"pair.t_hat[{index}]", _sub(_mul(x0, raw1), _mul(x1, raw0)), x_first.mul(actual1).sub(x_second.mul(actual0)))
    for index, (z0_value, z1_value) in enumerate(zip(first.response_zb, second.response_zb)):
        z0 = _center(z0_value)
        z1 = _center(z1_value)
        state.record(f"pair.r_t_hat[{index}]", _sub(_mul(x0, z1), _mul(x1, z0)), x_first.mul(z1_value).sub(x_second.mul(z0_value)))
    h0_raw = tuple(tuple(_mul(value, _sub(x0, value)) for value in row) for row in g0_raw)
    h1_raw = tuple(tuple(_mul(value, _sub(x1, value)) for value in row) for row in g1_raw)
    h0_ring = tuple(tuple(value.mul(x_first.sub(value)) for value in row) for row in first.responses_g)
    h1_ring = tuple(tuple(value.mul(x_second.sub(value)) for value in row) for row in second.responses_g)
    for index, (raw0, raw1, actual0, actual1) in enumerate(zip(_flatten(h0_raw), _flatten(h1_raw), _flatten(h0_ring), _flatten(h1_ring))):
        state.record(f"pair.e_hat[{index}]", _sub(raw0, raw1), actual0.sub(actual1))
        state.record(f"pair.s_hat[{index}]", _sub(_mul(x0, raw1), _mul(x1, raw0)), x_first.mul(actual1).sub(x_second.mul(actual0)))
    for index, (zg0, zg1, actual0, actual1) in enumerate(zip((_center(value) for value in first.response_zg), (_center(value) for value in second.response_zg), first.response_zg, second.response_zg)):
        state.record(f"pair.r_e_hat[{index}]", _sub(zg0, zg1), actual0.sub(actual1))
        state.record(f"pair.r_f_hat[{index}]", _sub(_mul(x0, zg1), _mul(x1, zg0)), x_first.mul(actual1).sub(x_second.mul(actual0)))
    return PairIntegerTrace(first_report, second_report, state.finish())


__all__ = [
    "IntegerTraceError",
    "IntegerTraceObservation",
    "IntegerTraceReport",
    "PairIntegerTrace",
    "trace_protocol1_pair",
    "trace_protocol1_response",
]
