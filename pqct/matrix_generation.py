"""Seeded public HMC matrix generation for reproducible experiments.

This is a deterministic public-matrix generator, not a security parameter
instantiation. It uses SHAKE256 with domain-separated coordinates and maps
bytes to uniform coefficients in R_q via rejection sampling.
"""

from __future__ import annotations

from hashlib import shake_256
from typing import Sequence

from .hmc import HMCError, HMCKey
from .ring_commitment import RingElement, ToyParameters


def _sample_coefficients(seed: bytes, label: bytes, count: int, q: int) -> list[int]:
    if not seed or not label or count <= 0 or q <= 1:
        raise ValueError("invalid matrix sampler input")
    width = (q.bit_length() + 7) // 8
    limit = (1 << (8 * width)) - ((1 << (8 * width)) % q)
    stream = bytearray()
    counter = 0
    values: list[int] = []
    while len(values) < count:
        stream.extend(shake_256(seed + label + counter.to_bytes(8, "big")).digest(width * 64))
        counter += 1
        for offset in range(0, len(stream) - width + 1, width):
            candidate = int.from_bytes(stream[offset : offset + width], "big")
            if candidate < limit:
                values.append(candidate % q)
                if len(values) == count:
                    break
        stream = stream[(len(stream) // width) * width :]
    return values


def generate_hmc_key(
    seed: bytes,
    params: ToyParameters,
    randomness_width: int,
    message_width: int,
    ring_rows: int | None = None,
) -> HMCKey:
    """Generate a reproducible public HMC key for experiment vectors."""
    if not seed or randomness_width <= 0 or message_width <= 0:
        raise HMCError("invalid seeded HMC dimensions")
    rows = ring_rows if ring_rows is not None else params.n
    if rows <= 0:
        raise HMCError("ring row count must be positive")
    def matrix(width: int, matrix_label: bytes) -> tuple[tuple[RingElement, ...], ...]:
        domain = (
            b"PQCT-HMC-MATRIX-V1|" + matrix_label
            + params.n.to_bytes(4, "big")
            + params.q.to_bytes((params.q.bit_length() + 7) // 8, "big")
            + rows.to_bytes(4, "big")
            + width.to_bytes(4, "big")
        )
        values = _sample_coefficients(seed, domain, rows * width * params.n, params.q)
        cursor = 0
        result = []
        for row in range(rows):
            row_values = []
            for column in range(width):
                coeffs = values[cursor : cursor + params.n]
                cursor += params.n
                row_values.append(RingElement.from_coeffs(coeffs, params))
            result.append(tuple(row_values))
        return tuple(result)

    return HMCKey(
        G_r=matrix(randomness_width, b"R"),
        G_m=matrix(message_width, b"M"),
        params=params,
    )
