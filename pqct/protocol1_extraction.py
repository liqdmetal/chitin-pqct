"""Executable tiny-ring extractor for Gao Protocol 1's second layer.

This is a bounded research oracle, not a production proof extractor. It
implements the algebra that can be extracted from three accepting transcripts
with identical public statement, commitments, and zeta, but distinct x
challenges. It deliberately returns relaxed openings (challenge differences
remain as scalar/ring relaxation factors) instead of attempting inversion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .binary_protocol1_ring import RingProtocol1Proof
from .ring_commitment import RingElement


class ExtractionError(ValueError):
    """Malformed transcript family or inconsistent extracted equations."""


def _sub_vectors(left: Sequence[RingElement], right: Sequence[RingElement]) -> tuple[RingElement, ...]:
    if len(left) != len(right):
        raise ExtractionError("vector widths differ")
    return tuple(a.sub(b) for a, b in zip(left, right))


def _scale_vector(scalar: RingElement, values: Sequence[RingElement]) -> tuple[RingElement, ...]:
    return tuple(scalar.mul(value) for value in values)


def _check_same_commitments(transcripts: Sequence[RingProtocol1Proof]) -> None:
    if len(transcripts) != 3:
        raise ExtractionError("Protocol 1 extractor requires exactly three transcripts")
    first = transcripts[0]
    if any(
        (proof.commitment_e, proof.commitment_f, proof.commitment_g)
        != (first.commitment_e, first.commitment_f, first.commitment_g)
        for proof in transcripts[1:]
    ):
        raise ExtractionError("transcripts do not share E/F/G commitments")


@dataclass(frozen=True)
class RelaxedOpening:
    """Opening of y times a committed value, without inverting y."""

    relaxation: RingElement
    message: tuple[RingElement, ...]
    randomness: tuple[RingElement, ...]


@dataclass(frozen=True)
class SecondLayerPairExtraction:
    """One pairwise relaxed-opening extraction for two x challenges."""

    relaxation: RingElement
    opening_sum_b: RelaxedOpening
    opening_g: RelaxedOpening
    opening_e: RelaxedOpening
    opening_f: RelaxedOpening


@dataclass(frozen=True)
class SecondLayerExtraction:
    """Relaxed openings and consistency equations from three x transcripts."""

    first_delta: RingElement
    second_delta: RingElement
    opening_sum_b: RelaxedOpening
    opening_g: RelaxedOpening
    opening_e: RelaxedOpening
    opening_f: RelaxedOpening


@dataclass(frozen=True)
class FirstLayerExtraction:
    """S=2 relaxed openings for the individual public commitments."""

    relaxation: RingElement
    opening_b0: RelaxedOpening
    opening_b1: RelaxedOpening
    aggregate_message: tuple[RingElement, ...]
    aggregate_randomness: tuple[RingElement, ...]


def _difference(left: RingElement, right: RingElement) -> RingElement:
    if left.params != right.params:
        raise ExtractionError("challenge parameter mismatch")
    return left.sub(right)


def extract_second_layer(
    challenges: Sequence[RingElement],
    transcripts: Sequence[RingProtocol1Proof],
    zeta: RingElement,
    *,
    transcript_zetas: Sequence[RingElement] | None = None,
) -> SecondLayerExtraction:
    """Extract the relaxed second-layer openings from three x transcripts.

    The first two transcripts yield relaxation ``y = x0 - x1``. The first and
    third yield ``y' = x0 - x2``. For the batched G equation, the committed
    message is the zeta-weighted sum of ``g_i``. The E/F equations use the
    flattened per-vector quadratic message. No inverse or coefficient-field
    division is attempted.
    """
    _check_same_commitments(transcripts)
    xs = tuple(challenges)
    if transcript_zetas is not None:
        supplied_zetas = tuple(transcript_zetas)
        if len(supplied_zetas) != len(transcripts):
            raise ExtractionError("transcript zeta metadata length differs")
        if any(value.params != zeta.params for value in supplied_zetas):
            raise ExtractionError("transcript zeta parameter mismatch")
        if any(value != zeta for value in supplied_zetas):
            raise ExtractionError("transcripts do not share the supplied zeta")

    if len(xs) != 3 or any(x.params != xs[0].params for x in xs):
        raise ExtractionError("challenge dimensions differ")
    if zeta.params != xs[0].params:
        raise ExtractionError("zeta parameter mismatch")
    if len({x.encode() for x in xs}) != 3:
        raise ExtractionError("x challenges must be distinct")
    first, second, third = transcripts
    y01 = _difference(xs[0], xs[1])
    y02 = _difference(xs[0], xs[2])

    sum_b_01 = RelaxedOpening(
        y01,
        _sub_vectors(
            _weighted_g(first.responses_g, zeta),
            _weighted_g(second.responses_g, zeta),
        ),
        _sub_vectors(first.response_zb, second.response_zb),
    )

    # From x0*B+G = Com(M0; z0) and x1*B+G = Com(M1; z1):
    # y01*B = Com(M0-M1; z0-z1), and
    # y01*G = Com(x0*M1-x1*M0; x0*z1-x1*z0).
    weighted_first = _weighted_g(first.responses_g, zeta)
    weighted_second = _weighted_g(second.responses_g, zeta)
    opening_g = RelaxedOpening(
        y01,
        _sub_vectors(
            _scale_vector(xs[0], weighted_second),
            _scale_vector(xs[1], weighted_first),
        ),
        _sub_vectors(
            _scale_vector(xs[0], second.response_zb),
            _scale_vector(xs[1], first.response_zb),
        ),
    )

    h_first = _quadratic_message(first.responses_g, xs[0])
    h_second = _quadratic_message(second.responses_g, xs[1])
    _ = _quadratic_message(third.responses_g, xs[2])
    # y*E = Com(h0-h1; z_g0-z_g1).
    opening_e = RelaxedOpening(
        y01,
        _sub_vectors(h_first, h_second),
        _sub_vectors(first.response_zg, second.response_zg),
    )
    # y*F = Com(x0*h1-x1*h0; x0*z_g1-x1*z_g0).
    opening_f = RelaxedOpening(
        y01,
        _sub_vectors(
            _scale_vector(xs[0], h_second),
            _scale_vector(xs[1], h_first),
        ),
        _sub_vectors(
            _scale_vector(xs[0], second.response_zg),
            _scale_vector(xs[1], first.response_zg),
        ),
    )

    return SecondLayerExtraction(y01, y02, sum_b_01, opening_g, opening_e, opening_f)


def _extract_second_layer_pair(
    first: RingProtocol1Proof,
    second: RingProtocol1Proof,
    x_first: RingElement,
    x_second: RingElement,
    zeta: RingElement,
) -> SecondLayerPairExtraction:
    """Derive all four pairwise relaxed openings for a fixed zeta."""
    y = x_first.sub(x_second)
    weighted_first = _weighted_g(first.responses_g, zeta)
    weighted_second = _weighted_g(second.responses_g, zeta)
    sum_b = RelaxedOpening(
        y,
        _sub_vectors(weighted_first, weighted_second),
        _sub_vectors(first.response_zb, second.response_zb),
    )
    opening_g = RelaxedOpening(
        y,
        _sub_vectors(
            _scale_vector(x_first, weighted_second),
            _scale_vector(x_second, weighted_first),
        ),
        _sub_vectors(
            _scale_vector(x_first, second.response_zb),
            _scale_vector(x_second, first.response_zb),
        ),
    )
    h_first = _quadratic_message(first.responses_g, x_first)
    h_second = _quadratic_message(second.responses_g, x_second)
    opening_e = RelaxedOpening(
        y,
        _sub_vectors(h_first, h_second),
        _sub_vectors(first.response_zg, second.response_zg),
    )
    opening_f = RelaxedOpening(
        y,
        _sub_vectors(
            _scale_vector(x_first, h_second),
            _scale_vector(x_second, h_first),
        ),
        _sub_vectors(
            _scale_vector(x_first, second.response_zg),
            _scale_vector(x_second, first.response_zg),
        ),
    )
    return SecondLayerPairExtraction(y, sum_b, opening_g, opening_e, opening_f)


def extract_second_layer_pair(
    challenges: Sequence[RingElement],
    transcripts: Sequence[RingProtocol1Proof],
    zeta: RingElement,
    *,
    transcript_zetas: Sequence[RingElement] | None = None,
) -> SecondLayerPairExtraction:
    """Extract and return the complete pairwise second-layer openings."""
    if len(challenges) != 2 or len(transcripts) != 2:
        raise ExtractionError("pair extraction requires exactly two transcripts")
    first, second = tuple(transcripts)
    if (first.commitment_e, first.commitment_f, first.commitment_g) != (
        second.commitment_e, second.commitment_f, second.commitment_g
    ):
        raise ExtractionError("pair transcripts do not share E/F/G commitments")
    if transcript_zetas is not None:
        metadata = tuple(transcript_zetas)
        if len(metadata) != 2:
            raise ExtractionError("pair transcript zeta metadata length differs")
        if any(value.params != zeta.params for value in metadata):
            raise ExtractionError("pair transcript zeta parameter mismatch")
        if any(value != zeta for value in metadata):
            raise ExtractionError("pair transcripts do not share the supplied zeta")
    x_first, x_second = tuple(challenges)
    if x_first.params != x_second.params or zeta.params != x_first.params:
        raise ExtractionError("pair challenge parameter mismatch")
    if x_first == x_second:
        raise ExtractionError("pair x challenges must be distinct")
    return _extract_second_layer_pair(
        transcripts[0], transcripts[1], x_first, x_second, zeta,
    )


def validate_pairwise_negation(
    first: SecondLayerPairExtraction,
    reverse: SecondLayerPairExtraction,
) -> bool:
    """Check that reversing a transcript pair negates every extracted opening."""
    try:
        negate = lambda value: value.scalar_mul(-1)
        if first.relaxation != negate(reverse.relaxation):
            return False
        for left, right in (
            (first.opening_sum_b, reverse.opening_sum_b),
            (first.opening_g, reverse.opening_g),
            (first.opening_e, reverse.opening_e),
            (first.opening_f, reverse.opening_f),
        ):
            if left.message != tuple(negate(value) for value in right.message):
                return False
            if left.randomness != tuple(negate(value) for value in right.randomness):
                return False
        return True
    except (AttributeError, TypeError, ValueError):
        return False


def validate_pairwise_consistency(
    pair: SecondLayerPairExtraction,
    proof_first: RingProtocol1Proof,
    proof_second: RingProtocol1Proof,
    x_first: RingElement,
    x_second: RingElement,
    zeta: RingElement,
) -> bool:
    """Recompute a pair independently and compare all four openings."""
    try:
        expected = _extract_second_layer_pair(
            proof_first, proof_second, x_first, x_second, zeta,
        )
        return expected == pair
    except (ExtractionError, TypeError, ValueError):
        return False


def validate_third_x_transcript(
    extraction: SecondLayerExtraction,
    challenge: RingElement,
    proof: RingProtocol1Proof,
    zeta: RingElement,
) -> bool:
    """Check the third x transcript against openings from the first pair.

    This is an algebraic consistency check, not a binding reduction. It catches
    the common self-consistency trap where an extractor is tested only on the
    two transcripts used to construct its outputs and the third transcript is
    never checked.
    """
    try:
        if any(value.params != extraction.first_delta.params for value in (challenge, zeta)):
            return False
        weighted = _weighted_g(proof.responses_g, zeta)
        h = _quadratic_message(proof.responses_g, challenge)
        y = extraction.first_delta
        expected_g_message = tuple(
            challenge.mul(left).add(right)
            for left, right in zip(extraction.opening_sum_b.message, extraction.opening_g.message)
        )
        expected_g_randomness = tuple(
            challenge.mul(left).add(right)
            for left, right in zip(extraction.opening_sum_b.randomness, extraction.opening_g.randomness)
        )
        actual_g_message = tuple(y.mul(value) for value in weighted)
        actual_g_randomness = tuple(y.mul(value) for value in proof.response_zb)
        if expected_g_message != actual_g_message or expected_g_randomness != actual_g_randomness:
            return False
        expected_e_message = tuple(
            challenge.mul(left).add(right)
            for left, right in zip(extraction.opening_e.message, extraction.opening_f.message)
        )
        expected_e_randomness = tuple(
            challenge.mul(left).add(right)
            for left, right in zip(extraction.opening_e.randomness, extraction.opening_f.randomness)
        )
        actual_e_message = tuple(y.mul(value) for value in h)
        actual_e_randomness = tuple(y.mul(value) for value in proof.response_zg)
        return (
            expected_e_message == actual_e_message
            and expected_e_randomness == actual_e_randomness
        )
    except (TypeError, ValueError, IndexError):
        return False


def extract_first_layer_s2(
    challenges: Sequence[RingElement],
    aggregate_messages: Sequence[Sequence[RingElement]],
    aggregate_randomness: Sequence[Sequence[RingElement]],
) -> FirstLayerExtraction:
    """Extract relaxed openings for B0 and B1 from two zeta transcripts.

    Inputs are the two accepted openings of ``y(B0 + zeta*B1)`` obtained from
    the second layer, represented as ``(b0 + zeta*b1, r_b)``.  The extraction
    uses the paper's equations (34)-(37): it multiplies by
    ``y_zeta = zeta0-zeta1`` and never inverts a ring element.
    """
    if len(challenges) != 2 or len(aggregate_messages) != 2 or len(aggregate_randomness) != 2:
        raise ExtractionError("S=2 extraction requires two challenge branches")
    zeta0, zeta1 = tuple(challenges)
    if zeta0.params != zeta1.params:
        raise ExtractionError("zeta parameter mismatch")
    if zeta0.encode() == zeta1.encode():
        raise ExtractionError("aggregation challenges must be distinct")
    messages = tuple(tuple(row) for row in aggregate_messages)
    randomness = tuple(tuple(row) for row in aggregate_randomness)
    if not messages[0] or len(messages[0]) != len(messages[1]):
        raise ExtractionError("aggregate message widths differ")
    if len(randomness[0]) != len(randomness[1]) or not randomness[0]:
        raise ExtractionError("aggregate randomness widths differ")
    if any(value.params != zeta0.params for row in messages + randomness for value in row):
        raise ExtractionError("aggregate opening parameter mismatch")
    y_zeta = zeta0.sub(zeta1)
    # b_hat_1 = y_zeta * b_1 and r_hat_1 = r_b0-r_b1.
    opening_b1 = RelaxedOpening(
        y_zeta,
        _sub_vectors(messages[0], messages[1]),
        _sub_vectors(randomness[0], randomness[1]),
    )
    # b_hat_0 = y_zeta * b_0; r_hat_0 = y_zeta*r_b1-zeta1*r_hat_1.
    opening_b0 = RelaxedOpening(
        y_zeta,
        _sub_vectors(
            _scale_vector(zeta0, messages[1]),
            _scale_vector(zeta1, messages[0]),
        ),
        tuple(
            zeta0.mul(right).sub(zeta1.mul(left))
            for left, right in zip(randomness[0], randomness[1])
        ),
    )
    return FirstLayerExtraction(
        y_zeta, opening_b0, opening_b1,
        messages[0], randomness[0],
    )


def validate_first_layer_relation(
    extraction: FirstLayerExtraction,
    zeta: RingElement,
    aggregate_message: Sequence[RingElement],
    aggregate_randomness: Sequence[RingElement],
) -> bool:
    """Check the extracted openings against one supplied aggregate opening.

    This checks only the ring commitment algebra supplied by the caller; it
    does not establish HMC binding or that the aggregate opening came from an
    accepting transcript.
    """
    try:
        if zeta.params != extraction.relaxation.params:
            return False
        if len(aggregate_message) != len(extraction.opening_b0.message):
            return False
        if len(aggregate_randomness) != len(extraction.opening_b0.randomness):
            return False
        expected_message = tuple(
            extraction.opening_b0.message[index].add(
                zeta.mul(extraction.opening_b1.message[index])
            )
            for index in range(len(aggregate_message))
        )
        expected_randomness = tuple(
            extraction.opening_b0.randomness[index].add(
                zeta.mul(extraction.opening_b1.randomness[index])
            )
            for index in range(len(aggregate_randomness))
        )
        factor = extraction.relaxation
        actual_message = tuple(factor.mul(value) for value in aggregate_message)
        actual_randomness = tuple(factor.mul(value) for value in aggregate_randomness)
        return expected_message == actual_message and expected_randomness == actual_randomness
    except (TypeError, ValueError):
        return False


def _weighted_g(
    responses: Sequence[Sequence[RingElement]], zeta: RingElement,
) -> tuple[RingElement, ...]:
    if not responses or not responses[0]:
        raise ExtractionError("empty g response")
    width = len(responses[0])
    total = [RingElement.zero(zeta.params) for _ in range(width)]
    power = RingElement.from_coeffs((1,) + (0,) * (zeta.params.n - 1), zeta.params)
    for row in responses:
        if len(row) != width:
            raise ExtractionError("g response widths differ")
        for index, value in enumerate(row):
            total[index] = total[index].add(power.mul(value))
        power = power.mul(zeta)
    return tuple(total)


def _quadratic_message(
    responses: Sequence[Sequence[RingElement]], challenge: RingElement,
) -> tuple[RingElement, ...]:
    result: list[RingElement] = []
    for row in responses:
        for value in row:
            result.append(value.mul(challenge.sub(value)))
    return tuple(result)


__all__ = [
    "ExtractionError",
    "FirstLayerExtraction",
    "RelaxedOpening",
    "SecondLayerExtraction",
    "SecondLayerPairExtraction",
    "extract_first_layer_s2",
    "extract_second_layer",
    "extract_second_layer_pair",
    "validate_first_layer_relation",
    "validate_pairwise_consistency",
    "validate_pairwise_negation",
    "validate_third_x_transcript",
]
