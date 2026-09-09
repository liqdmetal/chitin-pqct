"""Bounded fixed-challenge honest/simulator comparison experiments.

This module compares finite toy distributions only. It deliberately keeps the
simulator's response sampler explicit and records rejection conditioning. The
result is an empirical finite-sample comparison, not a proof of SHVZK,
computational indistinguishability, soundness, Fiat--Shamir security, or
production security.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from decimal import Decimal
from typing import Sequence

from .binary_protocol1_ring import (
    RingProtocol1Error,
    RingProtocol1Parameters,
    RingProtocol1Proof,
    build_protocol1_ring_transcript,
    verify_protocol1_ring,
)
from .hmc import HMCKey, centered_coefficients
from .protocol1_sampling import (
    Protocol1DistributionParameters,
    Protocol1Masks,
    SamplingError,
    XofByteSource,
    build_rejection_plan,
    coefficient_vector,
    sample_box_ring_vector,
    sample_gaussian_ring_vector,
    sample_protocol1_masks,
)
from .protocol1_rejection_audit import RejectionAuditError, build_rejection_tuple_audit
from .protocol1_simulator import SimulationError, simulate_protocol1_ring
from .ring_commitment import RingElement
from .shvzk_empirical_stats import (
    CollisionAwareStats,
    MarginalIntegerStats,
    collision_aware_stats,
    marginal_integer_stats,
)


def _weighted(values: Sequence[Sequence[RingElement]], zeta: RingElement) -> tuple[RingElement, ...]:
    if not values or not values[0]:
        raise SHVZKComparisonError("empty response matrix")
    width = len(values[0])
    total = [RingElement.zero(zeta.params) for _ in range(width)]
    power = RingElement.from_coeffs((1,) + (0,) * (zeta.params.n - 1), zeta.params)
    for row in values:
        if len(row) != width or any(value.params != zeta.params for value in row):
            raise SHVZKComparisonError("response matrix dimensions or parameters differ")
        for index, value in enumerate(row):
            total[index] = total[index].add(power.mul(value))
        power = power.mul(zeta)
    return tuple(total)


class SHVZKComparisonError(ValueError):
    """Malformed comparison input."""


_REJECT = b"PQCT-SHVZK-COMPARE-REJECT-V1"


def _frame(*parts: bytes) -> bytes:
    output = bytearray(b"PQCT-SHVZK-COMPARE-V1")
    for part in parts:
        output.extend(len(part).to_bytes(8, "big"))
        output.extend(part)
    return bytes(output)


def _encode_vector(values: Sequence[RingElement]) -> bytes:
    return _frame(*(value.encode() for value in values))


def _encode_rows(values: Sequence[Sequence[RingElement]]) -> bytes:
    return _frame(*(_encode_vector(row) for row in values))


def encode_response_tuple(proof: RingProtocol1Proof) -> bytes:
    """Canonicalize only the response tuple ``(g,z_g,z_b)``."""
    return _frame(
        _encode_rows(proof.responses_g),
        _encode_vector(proof.response_zg),
        _encode_vector(proof.response_zb),
    )


def encode_fixed_transcript(
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    zeta: RingElement,
    challenge_x: RingElement,
    proof: RingProtocol1Proof,
) -> bytes:
    """Canonicalize the complete fixed-challenge public transcript."""
    if not statement:
        raise SHVZKComparisonError("statement cannot be empty")
    return _frame(
        statement,
        base_key.encode(), key_e.encode(), key_f.encode(), key_g.encode(),
        _encode_rows(bit_commitments), zeta.encode(), challenge_x.encode(),
        _encode_vector(proof.commitment_e), _encode_vector(proof.commitment_f),
        _encode_vector(proof.commitment_g), encode_response_tuple(proof),
    )


def _source(seed: bytes, label: bytes, index: int, attempt: int = 0) -> XofByteSource:
    if not seed or not label or index < 0 or attempt < 0:
        raise SHVZKComparisonError("invalid comparison source inputs")
    return XofByteSource(_frame(seed, label, index.to_bytes(8, "big"), attempt.to_bytes(8, "big")))


def _histogram_key(counter: Counter[bytes]) -> tuple[tuple[bytes, int], ...]:
    return tuple(sorted(counter.items()))


def _tv(left: Counter[bytes], right: Counter[bytes], sample_count: int) -> Decimal:
    if sample_count <= 0:
        raise SHVZKComparisonError("sample count must be positive")
    keys = set(left) | set(right)
    return min(Decimal(1), sum(abs(Decimal(left[key] - right[key])) / Decimal(2 * sample_count) for key in keys))


@dataclass(frozen=True)
class FixedChallengeComparison:
    """Empirical histograms for one fixed-challenge comparison."""

    samples: int
    honest_accepts: int
    simulator_accepts: int
    response_tv: Decimal
    transcript_tv: Decimal
    honest_response_histogram: tuple[tuple[bytes, int], ...]
    simulator_response_histogram: tuple[tuple[bytes, int], ...]
    honest_transcript_histogram: tuple[tuple[bytes, int], ...]
    simulator_transcript_histogram: tuple[tuple[bytes, int], ...]
    honest_conditioned_response_histogram: tuple[tuple[bytes, int], ...] = ()
    simulator_conditioned_response_histogram: tuple[tuple[bytes, int], ...] = ()
    honest_conditioned_transcript_histogram: tuple[tuple[bytes, int], ...] = ()
    simulator_conditioned_transcript_histogram: tuple[tuple[bytes, int], ...] = ()
    response_stats: CollisionAwareStats | None = None
    transcript_stats: CollisionAwareStats | None = None
    conditioned_response_tv: Decimal | None = None
    conditioned_transcript_tv: Decimal | None = None
    honest_rejection_rate: Decimal = Decimal(0)
    simulator_rejection_rate: Decimal = Decimal(0)
    honest_mean_log_acceptance: Decimal | None = None
    simulator_mean_log_acceptance: Decimal | None = None
    marginal_g_stats: "MarginalIntegerStats | None" = None
    marginal_zg_stats: "MarginalIntegerStats | None" = None
    marginal_zb_stats: "MarginalIntegerStats | None" = None
    honest_g_samples: tuple[int, ...] = ()
    honest_zg_samples: tuple[int, ...] = ()
    honest_zb_samples: tuple[int, ...] = ()

    @staticmethod
    def _items(histogram: tuple[tuple[bytes, int], ...]) -> tuple[bytes, ...]:
        return tuple(key for key, count in histogram for _ in range(count))

    def binned_stats(self, prefix_bytes: int = 2) -> tuple[CollisionAwareStats, CollisionAwareStats]:
        left_response = self._items(self.honest_response_histogram)
        right_response = self._items(self.simulator_response_histogram)
        left_transcript = self._items(self.honest_transcript_histogram)
        right_transcript = self._items(self.simulator_transcript_histogram)
        return (
            collision_aware_stats(left_response, right_response, prefix_bytes=prefix_bytes),
            collision_aware_stats(left_transcript, right_transcript, prefix_bytes=prefix_bytes),
        )

    def digest_stats(self, digest_bytes: int = 2) -> tuple[CollisionAwareStats, CollisionAwareStats]:
        from .shvzk_empirical_stats import collision_aware_digest_stats
        left_response = self._items(self.honest_response_histogram)
        right_response = self._items(self.simulator_response_histogram)
        left_transcript = self._items(self.honest_transcript_histogram)
        right_transcript = self._items(self.simulator_transcript_histogram)
        return (
            collision_aware_digest_stats(left_response, right_response, digest_bytes=digest_bytes),
            collision_aware_digest_stats(left_transcript, right_transcript, digest_bytes=digest_bytes),
        )

    @property
    def honest_acceptance_rate(self) -> Decimal:
        return Decimal(self.honest_accepts) / Decimal(self.samples)

    @property
    def simulator_acceptance_rate(self) -> Decimal:
        return Decimal(self.simulator_accepts) / Decimal(self.samples)


def _sample_simulator_responses(
    source: XofByteSource,
    ring_params,
    vector_count: int,
    bit_width: int,
    randomness_width: int,
    p: int,
    w: int,
    distribution: Protocol1DistributionParameters,
    zeta: RingElement,
) -> tuple[
    tuple[tuple[RingElement, ...], ...],
    tuple[RingElement, ...],
    tuple[RingElement, ...],
    tuple[tuple[RingElement, ...], ...],
    Protocol1Masks,
]:
    masks = sample_protocol1_masks(
        source,
        ring_params,
        vector_count,
        bit_width,
        randomness_width,
        p,
        w,
        distribution,
    )
    responses_g = masks.t
    response_zg = sample_gaussian_ring_vector(
        source, ring_params, randomness_width, masks.opening_profile,
    )
    response_zb_components = tuple(
        sample_gaussian_ring_vector(
            source, ring_params, randomness_width, masks.opening_profile,
        )
        for _ in range(vector_count)
    )
    return (
        responses_g,
        response_zg,
        _weighted(response_zb_components, zeta),
        response_zb_components,
        masks,
    )


def _constant_bits(bits: Sequence[Sequence[RingElement]]) -> tuple[tuple[int, ...], ...]:
    output = []
    for row in bits:
        converted = []
        for bit in row:
            coefficients = centered_coefficients(bit)
            if coefficients[0] not in (0, 1) or any(value != 0 for value in coefficients[1:]):
                raise SHVZKComparisonError("comparison requires constant 0/1 ring bits")
            converted.append(coefficients[0])
        output.append(tuple(converted))
    return tuple(output)


def _opening_coefficients(openings: Sequence[Sequence[RingElement]]) -> tuple[tuple[int, ...], ...]:
    return tuple(tuple(coefficient_vector(row)) for row in openings)


def _rejection_for_masks(
    source: XofByteSource,
    masks: Protocol1Masks,
    challenge: RingElement,
    bits: Sequence[Sequence[int]],
    openings: Sequence[Sequence[int]],
    distribution: Protocol1DistributionParameters,
) -> tuple[bool, Decimal]:
    plan = build_rejection_plan(
        source,
        masks,
        centered_coefficients(challenge),
        bits,
        openings,
        distribution,
    )
    probability = plan.probability
    return plan.accepted, probability.ln() if probability > 0 else Decimal("-Infinity")


def _conditioned_tv(left: Counter[bytes], right: Counter[bytes], left_accepts: int, right_accepts: int) -> Decimal:
    if left_accepts <= 0 or right_accepts <= 0:
        return Decimal(1)
    keys = (set(left) | set(right)) - {_REJECT}
    return min(Decimal(1), sum(abs(Decimal(left[key]) / Decimal(left_accepts) - Decimal(right[key]) / Decimal(right_accepts)) / Decimal(2) for key in keys))


def compare_fixed_challenge(
    seed: bytes, statement: bytes, base_key: HMCKey, key_e: HMCKey, key_f: HMCKey, key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]], bits: Sequence[Sequence[RingElement]],
    openings: Sequence[Sequence[RingElement]], p: int, w: int,
    distribution: Protocol1DistributionParameters, params: RingProtocol1Parameters,
    zeta: RingElement, challenge_x: RingElement, samples: int,
    *,
    g_position: tuple[int, int] = (0, 0),
) -> FixedChallengeComparison:
    """Compare honest and simulated finite fixed-challenge transcript laws.

    ``g_position`` selects which (row, column) g_{i,j} marginal to collect.
    Lemma 6's witness-hiding is only observable at a position whose TRUE bit
    is 1 (honest g = x*b + t carries a witness-dependent shift that Rej must
    flatten); at a b=0 position there is no shift to hide, so the marginal
    says nothing about the flattening mechanism. Callers testing Lemma 6
    behavior must point this at a witness-bearing position.
    """
    if len(g_position) != 2 or g_position[0] < 0 or g_position[1] < 0:
        raise SHVZKComparisonError("g_position must be a nonnegative (row, column)")
    if not seed or not statement or samples <= 0:
        raise SHVZKComparisonError("seed, statement, and samples must be positive")
    if any(key.params != base_key.params for key in (key_e, key_f, key_g)):
        raise SHVZKComparisonError("commitment-key parameter mismatch")
    if zeta.params != base_key.params or challenge_x.params != base_key.params:
        raise SHVZKComparisonError("challenge parameter mismatch")
    public = tuple(tuple(row) for row in bit_commitments)
    normalized_bits = tuple(tuple(row) for row in bits)
    normalized_openings = tuple(tuple(row) for row in openings)
    if not public or len(public) != len(normalized_bits) or len(public) != len(normalized_openings):
        raise SHVZKComparisonError("public/witness dimensions differ")
    width = len(normalized_bits[0])
    if g_position[0] >= len(normalized_bits) or g_position[1] >= width:
        raise SHVZKComparisonError("g_position out of bounds for the witness matrix")
    honest_response = Counter[bytes](); simulator_response = Counter[bytes]()
    honest_transcript = Counter[bytes](); simulator_transcript = Counter[bytes]()
    honest_conditioned_response = Counter[bytes](); simulator_conditioned_response = Counter[bytes]()
    honest_conditioned_transcript = Counter[bytes](); simulator_conditioned_transcript = Counter[bytes]()
    honest_accepts = 0; simulator_accepts = 0
    honest_logs: list[Decimal] = []; simulator_logs: list[Decimal] = []
    honest_g_coeffs: list[int] = []; simulator_g_coeffs: list[int] = []
    honest_zg_coeffs: list[int] = []; simulator_zg_coeffs: list[int] = []
    honest_zb_coeffs: list[int] = []; simulator_zb_coeffs: list[int] = []
    _, opening_profile, _, _ = distribution.profiles(p, w, width, base_key.randomness_width, base_key.params.n)
    for index in range(samples):
        honest_proof = None; simulator_proof = None
        honest_ok = False; simulator_ok = False
        honest_per_index_zb = None
        try:
            masks = sample_protocol1_masks(_source(seed, b"honest-masks", index), base_key.params, len(normalized_bits), width, base_key.randomness_width, p, w, distribution)
            honest_proof = build_protocol1_ring_transcript(statement, base_key, key_e, key_f, key_g, public, normalized_bits, normalized_openings, masks.t, masks.r_e, masks.r_f, masks.r_t, params, zeta=zeta, challenge_x=challenge_x)
            honest_ok = verify_protocol1_ring(statement, base_key, key_e, key_f, key_g, public, honest_proof, params, zeta=zeta, challenge_x=challenge_x)
            if honest_ok:
                per_index_zb = tuple(
                    tuple(
                        challenge_x.mul(normalized_openings[row][column]).add(masks.r_t[row][column])
                        for column in range(base_key.randomness_width)
                    )
                    for row in range(len(normalized_openings))
                )
                honest_per_index_zb = per_index_zb
                audit = build_rejection_tuple_audit(
                    challenge=challenge_x,
                    bits=_constant_bits(normalized_bits),
                    t=masks.t,
                    r_e=masks.r_e,
                    r_f=masks.r_f,
                    openings=normalized_openings,
                    r_t=masks.r_t,
                    responses_g=honest_proof.responses_g,
                    response_zg=honest_proof.response_zg,
                    response_zb_by_index=per_index_zb,
                )
                del audit
                plan = build_rejection_plan(
                    _source(seed, b"honest-rejection", index),
                    masks,
                    centered_coefficients(challenge_x),
                    _constant_bits(normalized_bits),
                    _opening_coefficients(normalized_openings),
                    distribution,
                )
                honest_ok = plan.accepted
                if honest_ok:
                    honest_logs.append(plan.probability.ln() if plan.probability > 0 else Decimal("-Infinity"))
        except (RingProtocol1Error, SamplingError, TypeError, ValueError):
            honest_ok = False
        try:
            responses_g, response_zg, response_zb, response_zb_components, _sim_masks = _sample_simulator_responses(
                _source(seed, b"simulator-responses", index),
                base_key.params, len(normalized_bits), width,
                base_key.randomness_width, p, w, distribution, zeta,
            )
            simulated = simulate_protocol1_ring(
                statement, base_key, key_e, key_f, key_g, public,
                zeta, challenge_x, responses_g, response_zg, response_zb,
                params,
                commitment_e_randomness=sample_gaussian_ring_vector(
                    _source(seed, b"simulator-E-randomness", index),
                    base_key.params, base_key.randomness_width, opening_profile,
                ),
                response_zb_components=response_zb_components,
            )
            simulator_proof = simulated.proof
            simulator_ok = verify_protocol1_ring(statement, base_key, key_e, key_f, key_g, public, simulator_proof, params, zeta=zeta, challenge_x=challenge_x)
            # Per Gao Appendix B's SHVZK construction, the simulator draws
            # g_i,j ~ D_{1,T1}^d and (z_g,(z_b,i)) ~ D_{2,T2}^{md} DIRECTLY --
            # these ARE the target laws that honest Rej() acceptance converges
            # to (Lemma 6). There is no separate simulator-side rejection gate;
            # acceptance here is purely the verifier's equation/norm check.
        except (SimulationError, SamplingError, TypeError, ValueError):
            simulator_ok = False
        if honest_ok and honest_proof is not None:
            honest_accepts += 1; response = encode_response_tuple(honest_proof); transcript = encode_fixed_transcript(statement, base_key, key_e, key_f, key_g, public, zeta, challenge_x, honest_proof); honest_response[response] += 1; honest_transcript[transcript] += 1; honest_conditioned_response[response] += 1; honest_conditioned_transcript[transcript] += 1
            honest_g_coeffs.extend(centered_coefficients(honest_proof.responses_g[g_position[0]][g_position[1]]))
            honest_zg_coeffs.extend(centered_coefficients(honest_proof.response_zg[0]))
            if honest_per_index_zb is not None:
                honest_zb_coeffs.extend(
                    centered_coefficients(honest_per_index_zb[0][0])
                )
        else:
            honest_response[_REJECT] += 1; honest_transcript[_REJECT] += 1
        if simulator_ok and simulator_proof is not None:
            simulator_accepts += 1; response = encode_response_tuple(simulator_proof); transcript = encode_fixed_transcript(statement, base_key, key_e, key_f, key_g, public, zeta, challenge_x, simulator_proof); simulator_response[response] += 1; simulator_transcript[transcript] += 1; simulator_conditioned_response[response] += 1; simulator_conditioned_transcript[transcript] += 1
            simulator_g_coeffs.extend(centered_coefficients(simulator_proof.responses_g[g_position[0]][g_position[1]]))
            simulator_zg_coeffs.extend(centered_coefficients(simulator_proof.response_zg[0]))
            if response_zb_components:
                simulator_zb_coeffs.extend(
                    centered_coefficients(response_zb_components[0][0])
                )
        else:
            simulator_response[_REJECT] += 1; simulator_transcript[_REJECT] += 1
    response_items = lambda counter: tuple(key for key, count in counter.items() for _ in range(count))
    return FixedChallengeComparison(
        samples=samples, honest_accepts=honest_accepts, simulator_accepts=simulator_accepts,
        response_tv=_tv(honest_response, simulator_response, samples), transcript_tv=_tv(honest_transcript, simulator_transcript, samples),
        honest_response_histogram=_histogram_key(honest_response), simulator_response_histogram=_histogram_key(simulator_response),
        honest_transcript_histogram=_histogram_key(honest_transcript), simulator_transcript_histogram=_histogram_key(simulator_transcript),
        honest_conditioned_response_histogram=_histogram_key(honest_conditioned_response), simulator_conditioned_response_histogram=_histogram_key(simulator_conditioned_response),
        honest_conditioned_transcript_histogram=_histogram_key(honest_conditioned_transcript), simulator_conditioned_transcript_histogram=_histogram_key(simulator_conditioned_transcript),
        response_stats=collision_aware_stats(response_items(honest_response), response_items(simulator_response), prefix_bytes=2),
        transcript_stats=collision_aware_stats(response_items(honest_transcript), response_items(simulator_transcript), prefix_bytes=2),
        conditioned_response_tv=_conditioned_tv(honest_conditioned_response, simulator_conditioned_response, honest_accepts, simulator_accepts),
        conditioned_transcript_tv=_conditioned_tv(honest_conditioned_transcript, simulator_conditioned_transcript, honest_accepts, simulator_accepts),
        honest_rejection_rate=Decimal(samples - honest_accepts) / Decimal(samples), simulator_rejection_rate=Decimal(samples - simulator_accepts) / Decimal(samples),
        honest_mean_log_acceptance=sum(honest_logs, Decimal(0)) / Decimal(len(honest_logs)) if honest_logs else None,
        simulator_mean_log_acceptance=sum(simulator_logs, Decimal(0)) / Decimal(len(simulator_logs)) if simulator_logs else None,
        marginal_g_stats=marginal_integer_stats(honest_g_coeffs, simulator_g_coeffs) if honest_g_coeffs and simulator_g_coeffs else None,
        marginal_zg_stats=marginal_integer_stats(honest_zg_coeffs, simulator_zg_coeffs) if honest_zg_coeffs and simulator_zg_coeffs else None,
        marginal_zb_stats=marginal_integer_stats(honest_zb_coeffs, simulator_zb_coeffs) if honest_zb_coeffs and simulator_zb_coeffs else None,
        honest_g_samples=tuple(honest_g_coeffs),
        honest_zg_samples=tuple(honest_zg_coeffs),
        honest_zb_samples=tuple(honest_zb_coeffs),
    )


__all__ = ["FixedChallengeComparison", "SHVZKComparisonError", "compare_fixed_challenge", "encode_fixed_transcript", "encode_response_tuple"]
