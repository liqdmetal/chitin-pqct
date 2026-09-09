"""Explicit finite-distribution sampling for Gao Protocol 1 experiments.

The paper samples r_e from S_B^m and r_f, t_i, r_t,i from discrete-Gaussian
families, then applies Rej to the complete first and second response tuples.
This module implements that shape with a finite-support reference Gaussian and
injected deterministic bytes.

It is research code: inverse-CDF sampling is variable-time, finite support is
reported explicitly, and no constant-time, security, or production claim is
made.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from decimal import Decimal, getcontext
from hashlib import shake_256
from math import erfc, exp, pi, sqrt
from typing import Sequence

from .hmc import centered_coefficients
from .ring_commitment import RingElement, ToyParameters

getcontext().prec = 80


class SamplingError(ValueError):
    """Invalid sampling parameters or rejection input."""


class XofByteSource:
    """Deterministic injected byte source for reproducible experiment vectors."""

    def __init__(self, seed: bytes):
        if not seed:
            raise SamplingError("seed cannot be empty")
        self._seed = bytes(seed)
        self._counter = 0

    def read(self, count: int) -> bytes:
        if count < 0:
            raise SamplingError("byte count cannot be negative")
        output = bytearray()
        while len(output) < count:
            block = shake_256(
                b"PQCT-PROTOCOL1-RNG-V2"
                + len(self._seed).to_bytes(4, "big")
                + self._seed
                + self._counter.to_bytes(8, "big")
            ).digest(128)
            self._counter += 1
            output.extend(block)
        return bytes(output[:count])


def _uniform_bounded(source: XofByteSource, bound: int) -> int:
    if bound <= 0:
        raise SamplingError("uniform bound must be positive")
    width = max(1, (bound.bit_length() + 7) // 8)
    modulus = 1 << (8 * width)
    limit = modulus - (modulus % bound)
    while True:
        candidate = int.from_bytes(source.read(width), "big")
        if candidate < limit:
            return candidate % bound


def _uniform_unit(source: XofByteSource) -> Decimal:
    return Decimal(int.from_bytes(source.read(32), "big")) / Decimal(1 << 256)


@dataclass(frozen=True)
class FiniteDiscreteGaussian:
    """Normalized finite-support reference for D_sigma."""

    sigma: Decimal
    tail: int

    def __post_init__(self) -> None:
        if self.sigma <= 0 or self.tail < 0:
            raise SamplingError("sigma must be positive and tail nonnegative")
        denominator = Decimal(2) * self.sigma * self.sigma
        weights = tuple(
            (-(Decimal(value * value) / denominator)).exp()
            for value in range(-self.tail, self.tail + 1)
        )
        object.__setattr__(self, "_weights", weights)
        object.__setattr__(self, "_total_weight", sum(weights, Decimal(0)))
        # Cumulative table for O(log n) inversion sampling. The old sampler
        # did a linear CDF scan, O(support) per draw; with the ZK-grade tail
        # (13 sigma) the support is ~3100 for the paper's largest profile
        # and the scan dominated. bisect_right(cumulative, target) returns
        # the first index whose cumulative weight EXCEEDS target, which is
        # exactly the linear scan's "target < running" stopping point -- so
        # samples are byte-identical to the previous implementation for the
        # same seed. Verified against recorded test vectors.
        cumulative = []
        running = Decimal(0)
        for weight in weights:
            running += weight
            cumulative.append(running)
        object.__setattr__(self, "_cumulative", tuple(cumulative))

    @property
    def support(self) -> tuple[int, ...]:
        return tuple(range(-self.tail, self.tail + 1))

    @property
    def weights(self) -> tuple[Decimal, ...]:
        return self._weights

    @property
    def total_weight(self) -> Decimal:
        return self._total_weight

    @property
    def omitted_tail_bound(self) -> float:
        """Diagnostic upper bound for omitted infinite-support mass."""
        first_omitted = self.tail + 1
        sigma = float(self.sigma)
        unnormalized = 2.0 * (
            exp(-(first_omitted * first_omitted) / (2.0 * sigma * sigma))
            + sigma * sqrt(pi / 2.0) * erfc(first_omitted / (sqrt(2.0) * sigma))
        )
        return min(1.0, unnormalized / float(self.total_weight))

    def sample(self, source: XofByteSource) -> int:
        target = _uniform_unit(source) * self.total_weight
        index = bisect_right(self._cumulative, target)
        if index >= len(self.support):
            return self.support[-1]
        return self.support[index]


def sample_box(source: XofByteSource, count: int, bound: int) -> tuple[int, ...]:
    """Sample count independent coefficients uniformly from [-bound, bound]."""
    if count < 0 or bound < 0:
        raise SamplingError("box dimensions and bound must be nonnegative")
    return tuple(_uniform_bounded(source, 2 * bound + 1) - bound for _ in range(count))


def sample_gaussian(source: XofByteSource, profile: FiniteDiscreteGaussian, count: int) -> tuple[int, ...]:
    if count < 0:
        raise SamplingError("Gaussian sample count cannot be negative")
    return tuple(profile.sample(source) for _ in range(count))


def _ring_vector(values: Sequence[int], params: ToyParameters, width: int) -> tuple[RingElement, ...]:
    if width < 0 or len(values) != width * params.n:
        raise SamplingError("ring-vector coefficient count mismatch")
    return tuple(
        RingElement.from_coeffs(values[index * params.n : (index + 1) * params.n], params)
        for index in range(width)
    )


def sample_box_ring_vector(source: XofByteSource, params: ToyParameters, width: int, bound: int) -> tuple[RingElement, ...]:
    return _ring_vector(sample_box(source, width * params.n, bound), params, width)


def sample_gaussian_ring_vector(
    source: XofByteSource,
    params: ToyParameters,
    width: int,
    profile: FiniteDiscreteGaussian,
) -> tuple[RingElement, ...]:
    return _ring_vector(sample_gaussian(source, profile, width * params.n), params, width)


def coefficient_vector(elements: Sequence[RingElement]) -> tuple[int, ...]:
    """Flatten ring elements into centered integer coefficients."""
    return tuple(value for element in elements for value in centered_coefficients(element))


def squared_l2(values: Sequence[int]) -> int:
    return sum(value * value for value in values)


@dataclass(frozen=True)
class RejectionPolicy:
    """Exact paper-shaped Rej policy for a shift bounded by T.

    The paper defines gamma = phi*T and
    mu(phi) = exp(1/(2*phi) + 1/(2*phi^2)). The optional response bound is
    only the verifier's public norm gate; it is not folded into mu.
    """

    phi: Decimal
    T: Decimal
    response_bound: Decimal | None = None

    def __post_init__(self) -> None:
        if self.phi <= 0 or self.T <= 0:
            raise SamplingError("rejection phi and T must be positive")
        if self.response_bound is not None and self.response_bound <= 0:
            raise SamplingError("response bound must be positive")

    @property
    def gamma(self) -> Decimal:
        return self.phi * self.T

    @property
    def log_mu(self) -> Decimal:
        return Decimal(1) / (Decimal(2) * self.phi) + Decimal(1) / (Decimal(2) * self.phi * self.phi)

    @property
    def mu(self) -> Decimal:
        return self.log_mu.exp()


def rejection_log_probability(
    response: Sequence[int],
    shift: Sequence[int],
    policy: RejectionPolicy,
) -> Decimal:
    """Return log(min(1, exp(Rej exponent))).

    The un-clipped exponent is
      (-2 <response,shift> + ||shift||^2)/(2 gamma^2) - log(mu(phi)).
    A shift with norm >= T is outside the paper's stated support condition.
    """
    if len(response) != len(shift) or not response:
        raise SamplingError("response and shift dimensions must match")
    response_norm = Decimal(squared_l2(response)).sqrt()
    shift_norm = Decimal(squared_l2(shift)).sqrt()
    if shift_norm >= policy.T:
        return Decimal("-Infinity")
    if policy.response_bound is not None and response_norm > policy.response_bound:
        return Decimal("-Infinity")
    inner = sum(a * b for a, b in zip(response, shift))
    numerator = Decimal(-2 * inner + squared_l2(shift))
    raw = numerator / (Decimal(2) * policy.gamma * policy.gamma) - policy.log_mu
    return min(Decimal(0), raw)


def accept_rejection(
    source: XofByteSource,
    response: Sequence[int],
    shift: Sequence[int],
    policy: RejectionPolicy,
) -> tuple[bool, Decimal]:
    """Apply one deterministic reference rejection decision."""
    log_probability = rejection_log_probability(response, shift, policy)
    if log_probability.is_infinite():
        return False, Decimal(0)
    probability = log_probability.exp()
    return _uniform_unit(source) < probability, probability


def _concat_coefficients(elements: Sequence[RingElement]) -> tuple[int, ...]:
    return coefficient_vector(elements)


def _negacyclic_mul(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    if len(left) != len(right) or not left:
        raise SamplingError("negacyclic operands must have equal nonzero length")
    n = len(left)
    output = [0] * n
    for i, left_value in enumerate(left):
        for j, right_value in enumerate(right):
            index = i + j
            if index < n:
                output[index] += left_value * right_value
            else:
                output[index - n] -= left_value * right_value
    return tuple(output)


def _ringwise_mul(challenge: Sequence[int], flat_values: Sequence[int], n: int) -> tuple[int, ...]:
    if len(challenge) != n or len(flat_values) % n:
        raise SamplingError("ringwise multiplication dimensions differ")
    return tuple(
        coefficient
        for offset in range(0, len(flat_values), n)
        for coefficient in _negacyclic_mul(challenge, flat_values[offset : offset + n])
    )


# ZK-grade tail, in sigmas. Derived in pqct.shvzk_bound: the composed SHVZK
# distance over the paper profile's 15,872 response coordinates reaches the
# Lemma-6 floor (2^-86) at ~12.35 sigma. 13 is the integer ceiling with a
# small margin. At the old default of 6 the bound was 2^-15 -- a 15-bit
# distinguisher, i.e. not zero-knowledge in any usable sense.
ZK_TAIL_SIGMAS = 13

# Kept ONLY for speed-sensitive toy fixtures that do not make a ZK claim.
FAST_TOY_TAIL_SIGMAS = 6


def tail_for_sigma(sigma: Decimal, multiplier: int = ZK_TAIL_SIGMAS, minimum: int = 8) -> int:
    """Support tail scaled to the distribution's OWN sigma.

    A single fixed tail shared by profiles with very different sigmas is a
    footgun: for the small-sigma profile the support is wastefully wide
    (slow sampling), and for the large-sigma profile it truncates so hard
    the result is near-uniform and fits nothing (this caused a real false
    REJECT in the goodness-of-fit work). Scaling per profile removes both
    failure modes.

    DEFAULT CHANGED 6 -> 13 (ZK_TAIL_SIGMAS). The truncation distance is
    erfc(T/(sigma*sqrt 2)), depending only on T/sigma: at 6 sigma it is
    ~2^-29 per coordinate REGARDLESS of sigma, and composed over the paper
    profile's 15,872 coordinates the SHVZK bound was 2^-15 -- truncation
    dominated the Lemma-6 floor by 71 bits. At 13 sigma the composed bound
    is 2^-86, at the floor. The shipped sampler now matches the bound it
    is analysed under. Pass multiplier=FAST_TOY_TAIL_SIGMAS explicitly for
    speed in fixtures that make no ZK claim.
    """
    if sigma <= 0:
        raise SamplingError("sigma must be positive")
    if multiplier <= 0 or minimum < 0:
        raise SamplingError("multiplier must be positive and minimum nonnegative")
    scaled = int((sigma * multiplier).to_integral_value(rounding="ROUND_CEILING"))
    return max(minimum, scaled)


def tail_for_target_distance(
    sigma: Decimal, coordinates: int, target_log2: int = -100, minimum: int = 8
) -> int:
    """Smallest tail whose COMPOSED truncation distance meets 2^target_log2.

    Composes over `coordinates` independently sampled coefficients (statistical
    distance is subadditive under products), so the per-coordinate budget is
    2^target_log2 / coordinates. Delegates the search to
    pqct.truncation_distance so there is one implementation of the bound.
    """
    from .truncation_distance import required_tail_for_target

    if sigma <= 0:
        raise SamplingError("sigma must be positive")
    if coordinates <= 0:
        raise SamplingError("coordinates must be positive")
    tail = required_tail_for_target(
        float(sigma), coordinates, target=2.0 ** target_log2
    )
    return max(minimum, tail)


@dataclass(frozen=True)
class Protocol1DistributionParameters:
    """Protocol 1 distribution knobs with the paper's T1/T2 formulas."""

    B: int
    gaussian_tail: int = 12
    phi1: Decimal = Decimal("1")
    phi2: Decimal = Decimal("2")
    auto_tail: bool = False

    def __post_init__(self) -> None:
        if self.B <= 0 or self.gaussian_tail < 0:
            raise SamplingError("B must be positive and Gaussian tail nonnegative")
        if self.phi1 <= 0 or self.phi2 <= 0:
            raise SamplingError("phi1 and phi2 must be positive")

    @staticmethod
    def t1(p: int, w: int, k: int) -> Decimal:
        if min(p, w, k) <= 0:
            raise SamplingError("p, w and k must be positive")
        return Decimal(p) * Decimal(2 * w * k).sqrt()

    @staticmethod
    def t2(B: int, w: int, p: int, m: int, d: int) -> Decimal:
        if min(B, w, p, m, d) <= 0:
            raise SamplingError("B, w, p, m and d must be positive")
        return Decimal(B * w * p) * Decimal(3 * m * d).sqrt()

    def profiles(
        self, p: int, w: int, k: int, m: int, d: int,
    ) -> tuple[FiniteDiscreteGaussian, FiniteDiscreteGaussian, Decimal, Decimal]:
        t1 = self.t1(p, w, k)
        t2 = self.t2(self.B, w, p, m, d)
        if self.auto_tail:
            t_tail = tail_for_sigma(self.phi1 * t1)
            opening_tail = tail_for_sigma(self.phi2 * t2)
        else:
            t_tail = self.gaussian_tail
            opening_tail = self.gaussian_tail
        return (
            FiniteDiscreteGaussian(self.phi1 * t1, t_tail),
            FiniteDiscreteGaussian(self.phi2 * t2, opening_tail),
            t1,
            t2,
        )


@dataclass(frozen=True)
class Protocol1Masks:
    r_e: tuple[RingElement, ...]
    r_f: tuple[RingElement, ...]
    t: tuple[tuple[RingElement, ...], ...]
    r_t: tuple[tuple[RingElement, ...], ...]
    t1: Decimal
    t2: Decimal
    t_profile: FiniteDiscreteGaussian
    opening_profile: FiniteDiscreteGaussian


def sample_protocol1_masks(
    source: XofByteSource,
    ring_params: ToyParameters,
    vector_count: int,
    bit_width: int,
    randomness_width: int,
    p: int,
    w: int,
    distribution: Protocol1DistributionParameters,
) -> Protocol1Masks:
    """Sample the paper-shaped r_e, r_f, t_i and r_t,i objects.

    Ring width ``d`` is ``ring_params.n`` and HMC randomness width ``m`` is
    ``randomness_width``. Thus m ring elements represent m*d integer samples.
    """
    if vector_count <= 0 or bit_width <= 0 or randomness_width <= 0:
        raise SamplingError("Protocol 1 dimensions must be positive")
    t_profile, opening_profile, t1, t2 = distribution.profiles(
        p, w, bit_width, randomness_width, ring_params.n
    )
    r_e = sample_box_ring_vector(source, ring_params, randomness_width, distribution.B)
    r_f = sample_gaussian_ring_vector(source, ring_params, randomness_width, opening_profile)
    t = tuple(
        sample_gaussian_ring_vector(source, ring_params, bit_width, t_profile)
        for _ in range(vector_count)
    )
    r_t = tuple(
        sample_gaussian_ring_vector(source, ring_params, randomness_width, opening_profile)
        for _ in range(vector_count)
    )
    return Protocol1Masks(r_e, r_f, t, r_t, t1, t2, t_profile, opening_profile)


@dataclass(frozen=True)
class Protocol1RejectionPlan:
    """Both paper Rej decisions and their exact probabilities."""

    first: tuple[bool, Decimal]
    second: tuple[bool, Decimal]
    first_policy: RejectionPolicy
    second_policy: RejectionPolicy

    @property
    def accepted(self) -> bool:
        return self.first[0] and self.second[0]

    @property
    def probability(self) -> Decimal:
        return self.first[1] * self.second[1]


def build_rejection_plan(
    source: XofByteSource,
    masks: Protocol1Masks,
    challenge_coefficients: Sequence[int],
    bit_coefficients: Sequence[Sequence[int]],
    opening_coefficients: Sequence[Sequence[int]],
    params: Protocol1DistributionParameters,
) -> Protocol1RejectionPlan:
    """Apply Protocol 1 Steps 8 and 10 to complete integer tuples.

    ``bit_coefficients[i]`` contains k scalar bits for b_i. Each opening row
    contains the m*d centered coefficients of r_{b,i}. Ring multiplication by
    the challenge is performed negacyclically, rather than coefficientwise.
    """
    count = len(masks.t)
    if len(bit_coefficients) != count or len(opening_coefficients) != count:
        raise SamplingError("rejection witness dimensions differ")
    if len(challenge_coefficients) != masks.t[0][0].params.n:
        raise SamplingError("challenge coefficient dimension differs from ring degree")
    width = len(masks.t[0])
    if any(len(row) != width for row in bit_coefficients):
        raise SamplingError("bit coefficient dimensions differ")
    if any(value not in (0, 1) for row in bit_coefficients for value in row):
        raise SamplingError("rejection bit coefficients must be 0 or 1")

    n = len(challenge_coefficients)
    t_coefficients = _concat_coefficients(tuple(value for row in masks.t for value in row))
    zero_ring = (0,) * n
    first_shift = tuple(
        coefficient
        for row in bit_coefficients
        for bit in row
        for coefficient in (challenge_coefficients if bit else zero_ring)
    )
    first_response = tuple(a + b for a, b in zip(first_shift, t_coefficients))
    first_policy = RejectionPolicy(params.phi1, masks.t1)
    first = accept_rejection(source, first_response, first_shift, first_policy)

    rf_coefficients = _concat_coefficients(masks.r_f)
    re_coefficients = _concat_coefficients(masks.r_e)
    rt_rows = tuple(_concat_coefficients(row) for row in masks.r_t)
    expected_opening_width = len(re_coefficients)
    if any(len(row) != expected_opening_width for row in opening_coefficients):
        raise SamplingError("r_b opening dimensions differ")
    re_shift = _ringwise_mul(challenge_coefficients, re_coefficients, n)
    rb_shifts = tuple(
        _ringwise_mul(challenge_coefficients, row, n)
        for row in opening_coefficients
    )
    second_shift = re_shift + tuple(value for row in rb_shifts for value in row)
    z_g_response = tuple(a + b for a, b in zip(re_shift, rf_coefficients))
    z_b_response = tuple(
        value
        for shift, mask in zip(rb_shifts, rt_rows)
        for value in tuple(a + b for a, b in zip(shift, mask))
    )
    second_response = z_g_response + z_b_response
    second_policy = RejectionPolicy(params.phi2, masks.t2)
    if not first[0]:
        second = (False, Decimal(0))
    else:
        second = accept_rejection(source, second_response, second_shift, second_policy)
    return Protocol1RejectionPlan(first, second, first_policy, second_policy)


__all__ = [
    "FiniteDiscreteGaussian",
    "Protocol1DistributionParameters",
    "Protocol1Masks",
    "Protocol1RejectionPlan",
    "RejectionPolicy",
    "SamplingError",
    "XofByteSource",
    "accept_rejection",
    "build_rejection_plan",
    "coefficient_vector",
    "rejection_log_probability",
    "sample_box",
    "sample_gaussian",
    "sample_protocol1_masks",
    "squared_l2",
    "tail_for_sigma",
]
