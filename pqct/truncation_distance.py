"""Statistical distance of the finite-support Gaussian from the true D_sigma.

WHY THIS IS LOAD-BEARING
------------------------
Every rejection stage in this codebase (D_1, D_2, D_3) samples from
`FiniteDiscreteGaussian`, a TRUNCATED reference, while Gao's Lemmas 6/7 are
statements about the exact infinite discrete Gaussian D_sigma over Z. Three
separate open items rest on that gap. This module closes the measurable part
of it: exactly how far the truncated law is from the real one, and what that
costs once composed across a whole transcript.

THE EXACT PER-COORDINATE DISTANCE (an identity, not an estimate)
----------------------------------------------------------------
Write rho(x) = exp(-x^2 / (2 sigma^2)), S_T = sum_{|x|<=T} rho(x),
S_inf = sum_{x in Z} rho(x), and tail = S_inf - S_T. The truncated law is
rho(x)/S_T on [-T,T]; the true law is rho(x)/S_inf on Z. Then

    SD = 1/2 * [ sum_{|x|<=T} rho(x) * |1/S_T - 1/S_inf|
                 + sum_{|x|>T} rho(x)/S_inf ]
       = 1/2 * [ S_T*(1/S_T - 1/S_inf) + tail/S_inf ]
       = 1/2 * [ (S_inf - S_T)/S_inf + tail/S_inf ]
       = tail / S_inf.

So the statistical distance IS the omitted mass fraction -- exactly, with no
slack. `exact_statistical_distance` computes it directly.

A RIGOROUS CLOSED FORM
----------------------
For a certified bound (rather than a computed sum) note rho is decreasing on
x > 0, so

    tail = 2 * sum_{x>T} rho(x) <= 2 * int_T^inf rho(t) dt
         = 2 * sigma * sqrt(pi/2) * erfc( T / (sigma*sqrt 2) )

and by Poisson summation S_inf = sigma*sqrt(2 pi)*(1 + 2*sum_{k>=1}
exp(-2 pi^2 sigma^2 k^2)) >= sigma*sqrt(2 pi). Dividing, the sigma cancels:

    SD <= erfc( T / (sigma * sqrt 2) ).

Clean, sigma-free in form, and monotone in the number of standard deviations
T/sigma. With T = c*sigma it is just erfc(c/sqrt 2): c ~ 11.5 buys 2^-100.

COMPOSITION
-----------
Sampling N coordinates independently multiplies the distributions, and
statistical distance is subadditive under products (standard hybrid
argument):

    SD(P^N, Q^N) <= N * SD(P, Q).

A transcript draws N = (elements * degree) coefficients per Gaussian
profile, so the transcript-level bound is the sum over profiles of
N_profile * eps_profile. `transcript_distance` does that accounting, and
`required_tail_for_target` inverts it to answer the only question that
matters operationally: how large must the tail be so the WHOLE transcript
sits within 2^-100?

HONEST SCOPE
------------
This bounds the truncation gap only. It does not establish SHVZK, and it
does not address the OTHER approximation in the sampler (Decimal-precision
weight computation). It converts "the samplers are finite-support
references, distance unknown" into a number.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from decimal import Decimal

from .protocol1_sampling import FiniteDiscreteGaussian, SamplingError


class DistanceError(ValueError):
    """Raised on non-physical statistical-distance inputs."""


def _rho(value: int, sigma: float) -> float:
    return math.exp(-(value * value) / (2.0 * sigma * sigma))


def exact_statistical_distance(profile: FiniteDiscreteGaussian,
                               extra_terms: int = 4000) -> float:
    """SD(truncated, true) = tail_mass / S_inf, computed directly.

    `extra_terms` controls how far past the truncation point the reference
    sum is carried; rho decays superexponentially, so a few thousand terms
    past T is far beyond float resolution and the sum is effectively exact.
    """
    sigma = float(profile.sigma)
    tail = profile.tail
    if sigma <= 0:
        raise DistanceError("sigma must be positive")

    inside = sum(_rho(x, sigma) for x in range(-tail, tail + 1))
    outside = 2.0 * sum(
        _rho(x, sigma) for x in range(tail + 1, tail + 1 + extra_terms)
    )
    total = inside + outside
    if total <= 0:
        raise DistanceError("degenerate weight sum")
    return outside / total


def closed_form_bound(sigma: float, tail: int) -> float:
    """Rigorous upper bound erfc(T / (sigma*sqrt 2)) -- no summation.

    Derivation in the module docstring: the integral bound on the tail and
    the Poisson-summation lower bound on S_inf cancel sigma exactly.
    """
    if sigma <= 0:
        raise DistanceError("sigma must be positive")
    if tail < 0:
        raise DistanceError("tail must be non-negative")
    return math.erfc(tail / (sigma * math.sqrt(2.0)))


def sigmas_of_tail(sigma: float, tail: int) -> float:
    """How many standard deviations the truncation point sits at."""
    if sigma <= 0:
        raise DistanceError("sigma must be positive")
    return tail / sigma


@dataclass(frozen=True)
class ProfileDistance:
    """Truncation distance for one Gaussian profile, at one dimension."""

    name: str
    sigma: float
    tail: int
    coordinates: int
    exact_per_coordinate: float
    bound_per_coordinate: float

    @property
    def sigmas(self) -> float:
        return self.tail / self.sigma

    @property
    def composed_exact(self) -> float:
        return min(1.0, self.coordinates * self.exact_per_coordinate)

    @property
    def composed_bound(self) -> float:
        return min(1.0, self.coordinates * self.bound_per_coordinate)

    @property
    def bound_is_sound(self) -> bool:
        """The closed form must never sit BELOW the exact value."""
        return self.bound_per_coordinate >= self.exact_per_coordinate * 0.999999

    def log2_composed_bound(self) -> float:
        value = self.composed_bound
        return math.log2(value) if value > 0 else float("-inf")


def profile_distance(name: str, profile: FiniteDiscreteGaussian,
                     coordinates: int) -> ProfileDistance:
    sigma = float(profile.sigma)
    return ProfileDistance(
        name=name,
        sigma=sigma,
        tail=profile.tail,
        coordinates=coordinates,
        exact_per_coordinate=exact_statistical_distance(profile),
        bound_per_coordinate=closed_form_bound(sigma, profile.tail),
    )


@dataclass(frozen=True)
class TranscriptDistance:
    """Composed truncation distance for a whole transcript."""

    profiles: tuple
    target: float

    @property
    def total_exact(self) -> float:
        return min(1.0, sum(p.composed_exact for p in self.profiles))

    @property
    def total_bound(self) -> float:
        return min(1.0, sum(p.composed_bound for p in self.profiles))

    @property
    def meets_target(self) -> bool:
        return self.total_bound <= self.target

    @property
    def log2_total_bound(self) -> float:
        value = self.total_bound
        return math.log2(value) if value > 0 else float("-inf")

    def summary(self) -> dict:
        return {
            "profiles": [
                {
                    "name": p.name,
                    "sigma": p.sigma,
                    "tail": p.tail,
                    "sigmas": round(p.sigmas, 3),
                    "coordinates": p.coordinates,
                    "exact_per_coord": p.exact_per_coordinate,
                    "bound_per_coord": p.bound_per_coordinate,
                    "composed_bound": p.composed_bound,
                    "bound_sound": p.bound_is_sound,
                }
                for p in self.profiles
            ],
            "total_exact": self.total_exact,
            "total_bound": self.total_bound,
            "log2_total_bound": self.log2_total_bound,
            "target": self.target,
            "meets_target": self.meets_target,
        }


def transcript_distance(profiles, target: float = 2.0 ** -100
                        ) -> TranscriptDistance:
    """Compose per-profile distances into a transcript-level bound.

    `profiles` is an iterable of (name, FiniteDiscreteGaussian, coordinates).
    """
    items = tuple(
        profile_distance(name, profile, coordinates)
        for name, profile, coordinates in profiles
    )
    if not items:
        raise DistanceError("no profiles supplied")
    return TranscriptDistance(profiles=items, target=target)


def required_tail_for_target(sigma: float, coordinates: int,
                             target: float = 2.0 ** -100) -> int:
    """Smallest tail T with coordinates * erfc(T/(sigma*sqrt2)) <= target.

    This is the operationally useful direction: it answers "how wide must
    the support be" rather than "how bad is the support I picked".
    """
    if sigma <= 0:
        raise DistanceError("sigma must be positive")
    if coordinates <= 0:
        raise DistanceError("coordinates must be positive")
    if not 0 < target < 1:
        raise DistanceError("target must lie in (0,1)")

    per_coordinate = target / coordinates
    low, high = 0, max(8, int(math.ceil(sigma)) * 32)
    while closed_form_bound(sigma, high) > per_coordinate:
        high *= 2
        if high > 10 ** 7:
            raise DistanceError("required tail exceeds a sane search range")
    while low < high:
        middle = (low + high) // 2
        if closed_form_bound(sigma, middle) <= per_coordinate:
            high = middle
        else:
            low = middle + 1
    return low


__all__ = [
    "DistanceError",
    "ProfileDistance",
    "TranscriptDistance",
    "closed_form_bound",
    "exact_statistical_distance",
    "profile_distance",
    "required_tail_for_target",
    "sigmas_of_tail",
    "transcript_distance",
]
