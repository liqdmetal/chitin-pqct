"""Independent slow oracle for HMC arithmetic.

This module intentionally does not call HMCKey.commit or RingElement.mul. It
implements tuple-based negacyclic arithmetic separately so the optimized/
convenience path has a genuinely independent differential check.
"""

from __future__ import annotations

from itertools import product
from typing import Sequence


def negacyclic_mul(left: Sequence[int], right: Sequence[int], q: int) -> tuple[int, ...]:
    if len(left) != len(right) or not left:
        raise ValueError("polynomial dimensions must match")
    n = len(left)
    out = [0] * n
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            degree = i + j
            sign = -1 if degree >= n else 1
            out[degree % n] += sign * a * b
    return tuple(value % q for value in out)


def add(left: Sequence[int], right: Sequence[int], q: int) -> tuple[int, ...]:
    if len(left) != len(right):
        raise ValueError("vector dimensions must match")
    return tuple((a + b) % q for a, b in zip(left, right))


def matrix_commit(
    gr: Sequence[Sequence[Sequence[int]]],
    gm: Sequence[Sequence[Sequence[int]]],
    randomness: Sequence[Sequence[int]],
    message: Sequence[Sequence[int]],
    q: int,
) -> tuple[tuple[int, ...], ...]:
    rows = len(gr)
    if rows == 0 or len(gm) != rows:
        raise ValueError("matrix row dimensions differ")
    result = []
    for row in range(rows):
        if len(gr[row]) != len(randomness) or len(gm[row]) != len(message):
            raise ValueError("matrix column dimensions differ")
        total = tuple(0 for _ in randomness[0])
        for coefficient, value in zip(gr[row], randomness):
            total = add(total, negacyclic_mul(coefficient, value, q), q)
        for coefficient, value in zip(gm[row], message):
            total = add(total, negacyclic_mul(coefficient, value, q), q)
        result.append(total)
    return tuple(result)


def exhaustive_scalar_relations(width: int, modulus: int) -> tuple[tuple[int, ...], ...]:
    """Enumerate exact weighted-zero vectors for tiny bounded tests."""
    if width <= 0 or modulus <= 2:
        raise ValueError("invalid exhaustive dimensions")
    return tuple(
        values for values in product(range(-(modulus // 2), modulus // 2 + 1), repeat=width)
        if sum((1 << index) * value for index, value in enumerate(values)) == 0
    )
