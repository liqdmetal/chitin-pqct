"""Tiny-ring SHVZK simulator experiment for Gao Protocol 1.

The simulator follows Appendix B's stated construction: sample public response
values, choose E as a hiding commitment to zero, and solve F/G from the
verifier equations. It is an equation/distribution experiment only; it does
not establish the paper's computational indistinguishability claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .binary_protocol1_ring import RingProtocol1Parameters, RingProtocol1Proof
from .hmc import HMCError, HMCKey
from .ring_commitment import EncodingError, RingElement


class SimulationError(ValueError):
    """Malformed simulator input or equation failure."""


@dataclass(frozen=True)
class SimulatedProtocol1:
    proof: RingProtocol1Proof
    challenge: RingElement
    commitment_e_randomness: tuple[RingElement, ...]
    response_zb_components: tuple[tuple[RingElement, ...], ...]


def _zero(params) -> RingElement:
    return RingElement.zero(params)


def _weighted(
    values: Sequence[Sequence[RingElement]], zeta: RingElement,
) -> tuple[RingElement, ...]:
    if not values or not values[0]:
        raise SimulationError("empty response matrix")
    width = len(values[0])
    total = [_zero(zeta.params) for _ in range(width)]
    power = RingElement.from_coeffs(
        (1,) + (0,) * (zeta.params.n - 1), zeta.params,
    )
    for row in values:
        if len(row) != width or any(value.params != zeta.params for value in row):
            raise SimulationError("response matrix dimensions or parameters differ")
        for index, value in enumerate(row):
            total[index] = total[index].add(power.mul(value))
        power = power.mul(zeta)
    return tuple(total)


def _commitment_subtract(
    left: Sequence[RingElement],
    right: Sequence[RingElement],
    scalar: RingElement,
) -> tuple[RingElement, ...]:
    if len(left) != len(right):
        raise SimulationError("commitment dimensions differ")
    return tuple(a.sub(scalar.mul(b)) for a, b in zip(left, right))


def simulate_protocol1_ring_with_abort(
    *args,
    rejection_source,
    rejection_policy,
    **kwargs,
):
    """Simulator WITH the Lemma 6 abort stage. Returns (result, decision).

    `simulate_protocol1_ring` always succeeds, which makes it an unfair
    stand-in for the honest prover: the honest prover aborts at rate
    1 - 1/mu(phi), so its transcript distribution is conditioned on
    acceptance. A never-aborting simulator differs from it in acceptance
    RATE even when every accepted transcript is individually correct, and
    that rate is itself a distinguisher.

    Per Gao Lemma 6 the abort decision is WITNESS-INDEPENDENT (probability
    1/mu(phi), a function of phi alone), so the simulator can make it
    without knowing any secret -- which is precisely why simulating is
    possible at all.

    Returns (None, decision) when the simulator aborts, mirroring the
    honest prover's abort-and-retry loop.
    """
    from .simulator_rejection import simulate_rejection

    decision = simulate_rejection(rejection_source, rejection_policy)
    if not decision.accepted:
        return None, decision
    return simulate_protocol1_ring(*args, **kwargs), decision


def simulate_protocol1_ring(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    zeta: RingElement,
    challenge: RingElement,
    responses_g: Sequence[Sequence[RingElement]],
    response_zg: Sequence[RingElement],
    response_zb: Sequence[RingElement],
    params: RingProtocol1Parameters,
    *,
    commitment_e_randomness: Sequence[RingElement],
    response_zb_components: Sequence[Sequence[RingElement]] | None = None,
) -> SimulatedProtocol1:
    """Build a fixed-challenge transcript satisfying both public equations.

    ``response_zb`` is the public aggregate used in the proof. When the
    simulator samples the paper-shaped per-index values, callers must also
    provide ``response_zb_components``. The function verifies that their
    zeta-weighted aggregate equals ``response_zb`` and retains them in the
    returned metadata so Step 10 rejection analysis cannot silently lose them.
    """
    del statement, params
    if any(key.params != base_key.params for key in (key_e, key_f, key_g)):
        raise SimulationError("commitment-key parameter mismatch")
    if zeta.params != base_key.params or challenge.params != base_key.params:
        raise SimulationError("ring parameter mismatch")

    public = tuple(tuple(row) for row in bit_commitments)
    rows = tuple(tuple(row) for row in responses_g)
    if not public or len(rows) != len(public) or not rows[0]:
        raise SimulationError("simulated vector dimensions differ")
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise SimulationError("simulated response widths differ")
    if any(len(row) != base_key.ring_rows for row in public):
        raise SimulationError("public commitment row count differs")
    if len(response_zg) != key_e.randomness_width:
        raise SimulationError("simulated z_g opening dimensions differ")
    if len(response_zb) != key_g.randomness_width:
        raise SimulationError("simulated z_b opening dimensions differ")
    if len(commitment_e_randomness) != key_e.randomness_width:
        raise SimulationError("simulated E randomness dimensions differ")
    all_openings = (*response_zg, *response_zb, *commitment_e_randomness)
    if any(value.params != base_key.params for value in all_openings):
        raise SimulationError("simulated opening parameter mismatch")
    if key_e.message_width != len(rows) * width or key_f.message_width != len(rows) * width:
        raise SimulationError("E/F message dimensions differ")
    if key_g.message_width != width:
        raise SimulationError("G message dimension differs")

    if response_zb_components is None:
        components: tuple[tuple[RingElement, ...], ...] = ()
    else:
        components = tuple(tuple(row) for row in response_zb_components)
        if len(components) != len(rows):
            raise SimulationError("per-index z_b component count differs")
        if any(len(row) != key_g.randomness_width for row in components):
            raise SimulationError("per-index z_b component width differs")
        if any(value.params != base_key.params for row in components for value in row):
            raise SimulationError("per-index z_b component parameter mismatch")
        if _weighted(components, zeta) != tuple(response_zb):
            raise SimulationError("per-index z_b components do not aggregate to z_b")

    quadratic = tuple(
        value.mul(challenge.sub(value)) for row in rows for value in row
    )
    zero = tuple(_zero(base_key.params) for _ in quadratic)
    commitment_e = key_e.commit(zero, commitment_e_randomness)

    # z_g is the response opening used by the verifier; it is not the
    # randomness that created E.
    h_commitment = key_f.commit(quadratic, response_zg)
    commitment_f = _commitment_subtract(h_commitment, commitment_e, challenge)

    weighted_public = _weighted(public, zeta)
    weighted_response = _weighted(rows, zeta)
    target = key_g.commit(weighted_response, response_zb)
    commitment_g = _commitment_subtract(target, weighted_public, challenge)

    return SimulatedProtocol1(
        proof=RingProtocol1Proof(
            commitment_e, commitment_f, commitment_g,
            rows, tuple(response_zg), tuple(response_zb),
        ),
        challenge=challenge,
        commitment_e_randomness=tuple(commitment_e_randomness),
        response_zb_components=components,
    )


__all__ = ["SimulationError", "SimulatedProtocol1", "simulate_protocol1_ring"]
