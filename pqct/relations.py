"""Small, exact integer relation helpers for the PQ-CT research lab.

These helpers are deliberately not cryptographic proofs. They provide a
reference oracle for the amount-bit relation before a lattice transcript is
implemented.
"""

from __future__ import annotations


def decompose_unsigned(value: int, width: int) -> tuple[int, ...]:
    """Return the canonical little-endian bit vector for an unsigned value."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("value must be an integer")
    if width <= 0:
        raise ValueError("width must be positive")
    if value < 0 or value >= (1 << width):
        raise ValueError("value outside unsigned bit width")
    return tuple((value >> index) & 1 for index in range(width))


def weighted_relation(
    values: tuple[int, ...] | list[int],
    weights: tuple[int, ...] | list[int],
    width: int,
) -> int:
    """Evaluate Σ weight_i * value_i with range-checked unsigned values."""
    if len(values) != len(weights) or not values:
        raise ValueError("values and weights must have the same nonzero length")
    for value in values:
        decompose_unsigned(value, width)
    return sum(weight * value for value, weight in zip(values, weights))


def bit_columns(
    values: tuple[int, ...] | list[int],
    weights: tuple[int, ...] | list[int],
    width: int,
) -> tuple[int, ...]:
    """Return c_j = Σ_i weight_i * bit(value_i, j)."""
    if len(values) != len(weights) or not values:
        raise ValueError("values and weights must have the same nonzero length")
    bits = [decompose_unsigned(value, width) for value in values]
    return tuple(
        sum(weight * row[index] for weight, row in zip(weights, bits))
        for index in range(width)
    )


def packed_bit_relation(
    values: tuple[int, ...] | list[int],
    weights: tuple[int, ...] | list[int],
    width: int,
) -> int:
    """Pack the bit-column relation back into an exact integer."""
    return sum((1 << index) * column for index, column in enumerate(bit_columns(values, weights, width)))


def account_conservation(
    old_balance: int,
    credits: int,
    new_balance: int,
    debits: int,
    fee: int,
    width: int,
) -> bool:
    """Check the unsigned account conservation relation exactly."""
    values = (old_balance, credits, new_balance, debits, fee)
    weights = (1, 1, -1, -1, -1)
    return weighted_relation(values, weights, width) == 0
