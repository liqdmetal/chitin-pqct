"""Sampled, abort-and-retry Protocol 1 research wrapper.

This wrapper connects the finite-support sampler and the explicit two-stage
rejection decisions to the ring-valued Protocol 1 equation reference. It is
intentionally separate from the equation-only prover so an incomplete
parameter/distribution mapping cannot silently become a proof claim.

The result is a reproducible synthetic transcript only. It is not constant
 time, uses truncated reference Gaussians, and is not suitable for keys, money,
 consensus, or production cryptography.
"""

from __future__ import annotations

from dataclasses import dataclass

from .binary_protocol1_ring import (
    RingProtocol1Error,
    RingProtocol1Parameters,
    RingProtocol1Proof,
    _derive_x,
    _derive_zeta,
    prove_protocol1_ring,
    verify_protocol1_ring,
)
from .hmc import HMCKey, centered_coefficients
from .protocol1_sampling import (
    Protocol1DistributionParameters,
    Protocol1Masks,
    Protocol1RejectionPlan,
    SamplingError,
    XofByteSource,
    build_rejection_plan,
    coefficient_vector,
    sample_protocol1_masks,
)
from .ring_commitment import RingElement


class SampledProtocol1Error(ValueError):
    """Sampling, rejection, or self-verification failure."""


def _attempt_source(seed: bytes, label: bytes, attempt: int) -> XofByteSource:
    if not seed or not label or attempt < 0:
        raise SampledProtocol1Error("invalid attempt source inputs")
    material = (
        b"PQCT-PROTOCOL1-SAMPLED-V1"
        + len(seed).to_bytes(4, "big")
        + seed
        + len(label).to_bytes(2, "big")
        + label
        + attempt.to_bytes(8, "big")
    )
    return XofByteSource(material)


def _bit_scalars(bits: tuple[tuple[RingElement, ...], ...]) -> tuple[tuple[int, ...], ...]:
    result = []
    for row in bits:
        values = []
        for bit in row:
            coefficients = centered_coefficients(bit)
            if coefficients[0] not in (0, 1) or any(value != 0 for value in coefficients[1:]):
                raise SampledProtocol1Error("bits must be constant ring polynomials equal to 0 or 1")
            values.append(coefficients[0])
        result.append(tuple(values))
    return tuple(result)


def _opening_scalars(
    openings: tuple[tuple[RingElement, ...], ...],
    randomness_width: int,
) -> tuple[tuple[int, ...], ...]:
    result = []
    for row in openings:
        if len(row) != randomness_width:
            raise SampledProtocol1Error("opening width differs from HMC randomness width")
        result.append(coefficient_vector(row))
    return tuple(result)


@dataclass(frozen=True)
class SampledProtocol1Result:
    """A self-verified synthetic transcript and its experiment metadata."""

    proof: RingProtocol1Proof
    masks: Protocol1Masks
    rejection: Protocol1RejectionPlan
    zeta: RingElement
    x: RingElement
    attempts: int


def prove_protocol1_ring_sampled(
    seed: bytes,
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: tuple[tuple[RingElement, ...], ...],
    bits: tuple[tuple[RingElement, ...], ...],
    openings: tuple[tuple[RingElement, ...], ...],
    p: int,
    w: int,
    distribution: Protocol1DistributionParameters,
    params: RingProtocol1Parameters,
    max_attempts: int = 128,
) -> SampledProtocol1Result:
    """Produce a sampled Protocol 1 transcript with explicit abort/retry.

    The transcript is accepted only when both paper-shaped rejection stages
    pass, the declared verifier norm bounds pass, and the independent verifier
    accepts the resulting proof. Every attempt uses a domain-separated XOF
    stream, so an accepted vector is reproducible from ``seed`` and the attempt
    number.
    """
    if not seed or not statement:
        raise SampledProtocol1Error("seed and statement cannot be empty")
    if max_attempts <= 0:
        raise SampledProtocol1Error("max_attempts must be positive")
    bits_tuple = tuple(tuple(row) for row in bits)
    commitments_tuple = tuple(tuple(row) for row in bit_commitments)
    openings_tuple = tuple(tuple(row) for row in openings)
    if not bits_tuple or not bits_tuple[0]:
        raise SampledProtocol1Error("bit witness cannot be empty")
    if len(commitments_tuple) != len(bits_tuple) or len(openings_tuple) != len(bits_tuple):
        raise SampledProtocol1Error("witness and commitment dimensions differ")
    width = len(bits_tuple[0])
    if any(len(row) != width for row in bits_tuple):
        raise SampledProtocol1Error("bit widths differ")
    bit_scalars = _bit_scalars(bits_tuple)
    opening_scalars = _opening_scalars(openings_tuple, base_key.randomness_width)
    zeta = _derive_zeta(
        statement, base_key, key_e, key_f, key_g, commitments_tuple, params,
    )

    for attempt in range(1, max_attempts + 1):
        masks = sample_protocol1_masks(
            _attempt_source(seed, b"masks", attempt),
            base_key.params,
            len(bits_tuple),
            width,
            base_key.randomness_width,
            p,
            w,
            distribution,
        )
        try:
            proof = prove_protocol1_ring(
                statement,
                base_key,
                key_e,
                key_f,
                key_g,
                commitments_tuple,
                bits_tuple,
                openings_tuple,
                masks.t,
                masks.r_e,
                masks.r_f,
                masks.r_t,
                params,
                zeta=zeta,
            )
        except RingProtocol1Error:
            continue

        x = _derive_x(
            statement,
            base_key,
            key_e,
            key_f,
            key_g,
            commitments_tuple,
            (proof.commitment_e, proof.commitment_f, proof.commitment_g),
            zeta,
            params,
        )
        rejection = build_rejection_plan(
            _attempt_source(seed, b"rejection", attempt),
            masks,
            centered_coefficients(x),
            bit_scalars,
            opening_scalars,
            distribution,
        )
        if not rejection.accepted:
            continue
        if not verify_protocol1_ring(
            statement,
            base_key,
            key_e,
            key_f,
            key_g,
            commitments_tuple,
            proof,
            params,
        ):
            raise SampledProtocol1Error("accepted transcript failed independent verification")
        return SampledProtocol1Result(proof, masks, rejection, zeta, x, attempt)

    raise SampledProtocol1Error(
        f"no accepted Protocol 1 transcript in {max_attempts} deterministic attempts"
    )


__all__ = [
    "SampledProtocol1Error",
    "SampledProtocol1Result",
    "prove_protocol1_ring_sampled",
]
