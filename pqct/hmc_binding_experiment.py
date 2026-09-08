"""Bounded toy HMC binding/search experiments.

This is not a Module-SIS estimator or a security claim. It exhaustively searches
small centered message/opening differences and reports actual relaxed-opening
collisions for research diagnostics.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Sequence

from .hmc import HMCKey, bounded_ring_element
from .ring_commitment import RingElement


class BindingExperimentError(ValueError):
    pass


@dataclass(frozen=True)
class BindingCollision:
    delta_message: tuple[RingElement, ...]
    delta_randomness: tuple[RingElement, ...]
    commitment_difference: tuple[RingElement, ...]
    relaxation: RingElement


@dataclass(frozen=True)
class BindingSearchResult:
    relaxation: RingElement
    bound: int
    checked: int
    collisions: tuple[BindingCollision, ...]

    @property
    def binding_holds_in_box(self) -> bool:
        return not self.collisions


def _elements(params, bound: int):
    if bound < 0:
        raise BindingExperimentError("bound must be nonnegative")
    for values in product(range(-bound, bound + 1), repeat=params.n):
        yield bounded_ring_element(values, params)


def _vectors(params, width: int, bound: int):
    elements = tuple(_elements(params, bound))
    for values in product(elements, repeat=width):
        yield tuple(values)


def search_relaxed_collisions(
    key: HMCKey,
    relaxation: RingElement,
    message_bound: int,
    randomness_bound: int,
    *,
    max_collisions: int = 32,
) -> BindingSearchResult:
    """Search a bounded difference box for ``y*C_delta = 0`` collisions."""
    if relaxation.params != key.params:
        raise BindingExperimentError("parameter mismatch")
    if message_bound < 0 or randomness_bound < 0:
        raise BindingExperimentError("bounds must be nonnegative")
    if max_collisions <= 0:
        raise BindingExperimentError("max_collisions must be positive")
    messages = tuple(_vectors(key.params, key.message_width, message_bound))
    randomness = tuple(_vectors(key.params, key.randomness_width, randomness_bound))
    zero_message = tuple(RingElement.zero(key.params) for _ in range(key.message_width))
    zero_randomness = tuple(RingElement.zero(key.params) for _ in range(key.randomness_width))
    collisions = []
    checked = 0
    for message in messages:
        for opening in randomness:
            if message == zero_message and opening == zero_randomness:
                continue
            checked += 1
            difference = key.commit(message, opening)
            scaled = tuple(relaxation.mul(value) for value in difference)
            if all(value == RingElement.zero(key.params) for value in scaled):
                collisions.append(BindingCollision(message, opening, difference, relaxation))
                if len(collisions) >= max_collisions:
                    return BindingSearchResult(relaxation, max(message_bound, randomness_bound), checked, tuple(collisions))
    return BindingSearchResult(relaxation, max(message_bound, randomness_bound), checked, tuple(collisions))


__all__ = [
    "BindingCollision",
    "BindingExperimentError",
    "BindingSearchResult",
    "search_relaxed_collisions",
]
