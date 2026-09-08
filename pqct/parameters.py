"""Explicit parameter profiles and conservative toy accounting.

These profiles are research bookkeeping, not security claims. The 2021/1674
paper reports a concrete profile for 128-bit post-quantum targets under its
complete construction; this module records the source values and refuses to
pretend that a scalar/toy harness inherits that security.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil, log2


class ParameterError(ValueError):
    """Raised for invalid or internally inconsistent parameter profiles."""


@dataclass(frozen=True)
class GaoPaperProfile:
    """Paper-reported evaluation profile, kept separate from toy profiles."""

    security_label: str = "paper-reported 128-bit target; not independently verified"
    d: int = 64
    w: int = 56
    p: int = 8
    q: int = 2**49 - 2**18 + 2**9 + 1
    n: int = 29
    m: int = 60
    amount_bits: int = 64
    outputs: int = 1

    def validate(self) -> None:
        if self.d <= 1 or self.d & (self.d - 1):
            raise ParameterError("d must be a power of two greater than one")
        if not (0 < self.w <= self.d and self.p > 0):
            raise ParameterError("challenge weight parameters invalid")
        if self.q <= 2 or self.n <= 0 or self.m <= self.n:
            raise ParameterError("ring/module dimensions invalid")
        if self.amount_bits <= 0 or self.outputs <= 0:
            raise ParameterError("amount/output parameters invalid")

    @property
    def challenge_count_lower_bound(self) -> int:
        """Lower bound d choose w times (2p)^w from the paper's challenge set."""
        from math import comb
        return comb(self.d, self.w) * (2 * self.p) ** self.w

    @property
    def modulus_bits(self) -> int:
        return self.q.bit_length()


@dataclass(frozen=True)
class ToyProfile:
    """Small executable profile for tests; security level is exactly zero."""

    n: int = 4
    q: int = 12289
    randomness_width: int = 2
    message_width: int = 2
    challenge_bound: int = 31
    security_bits: int = 0

    def validate(self) -> None:
        if self.n <= 1 or self.q <= 2:
            raise ParameterError("toy ring dimensions invalid")
        if self.randomness_width <= 0 or self.message_width <= 0:
            raise ParameterError("toy vector widths invalid")
        if not 1 <= self.challenge_bound < self.q:
            raise ParameterError("toy challenge bound must fit the modulus")
        if self.security_bits != 0:
            raise ParameterError("toy profile security must remain zero")


def response_bound(challenge_bound: int, witness_bound: int, mask_bound: int) -> int:
    """Conservative scalar bound |x*witness + mask|."""
    if min(challenge_bound, witness_bound, mask_bound) < 0:
        raise ParameterError("bounds must be nonnegative")
    return challenge_bound * witness_bound + mask_bound


def cycle_mask_bound(sample_bound: int, width: int) -> int:
    """Worst-case infinity bound for d_j=d'_j-2d'_(j+1)."""
    if sample_bound < 0 or width < 2:
        raise ParameterError("cycle-mask inputs invalid")
    return 3 * sample_bound
