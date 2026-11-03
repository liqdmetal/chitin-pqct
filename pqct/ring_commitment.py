"""Small, auditable ring/module commitment model.

This is a correctness scaffold only. The parameters are deliberately toy-sized
and provide no security claim. Do not use for money, keys, or consensus.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable, Sequence


class EncodingError(ValueError):
    """Raised when a ring object is malformed or non-canonical."""


@dataclass(frozen=True)
class ToyParameters:
    """Toy ring parameters for reference tests."""

    n: int = 8
    q: int = 12289
    k: int = 2

    def __post_init__(self) -> None:
        if self.n <= 0 or self.n & (self.n - 1):
            raise ValueError("n must be a positive power of two")
        if self.q <= 2 or self.q % (2 * self.n) != 1:
            raise ValueError("q must satisfy q = 1 mod 2n")
        if self.k <= 0:
            raise ValueError("k must be positive")


@dataclass(frozen=True)
class RingElement:
    """Polynomial in Z_q[x]/(x^n+1), in canonical coefficient form."""

    coeffs: tuple[int, ...]
    params: ToyParameters

    def __post_init__(self) -> None:
        if len(self.coeffs) != self.params.n:
            raise EncodingError("wrong coefficient count")
        if any(c < 0 or c >= self.params.q for c in self.coeffs):
            raise EncodingError("coefficients are not canonical")

    @classmethod
    def zero(cls, params: ToyParameters) -> "RingElement":
        return cls((0,) * params.n, params)

    @classmethod
    def from_coeffs(
        cls, coeffs: Iterable[int], params: ToyParameters
    ) -> "RingElement":
        values = tuple(int(c) % params.q for c in coeffs)
        return cls(values, params)

    def add(self, other: "RingElement") -> "RingElement":
        self._same_params(other)
        return RingElement.from_coeffs(
            (a + b for a, b in zip(self.coeffs, other.coeffs)), self.params
        )

    def sub(self, other: "RingElement") -> "RingElement":
        self._same_params(other)
        return RingElement.from_coeffs(
            (a - b for a, b in zip(self.coeffs, other.coeffs)), self.params
        )

    def scalar_mul(self, scalar: int) -> "RingElement":
        return RingElement.from_coeffs(
            (scalar * a for a in self.coeffs), self.params
        )

    def mul(self, other: "RingElement") -> "RingElement":
        """Negacyclic polynomial multiplication modulo x^n+1."""
        self._same_params(other)
        out = [0] * self.params.n
        for i, a in enumerate(self.coeffs):
            for j, b in enumerate(other.coeffs):
                index = i + j
                if index >= self.params.n:
                    out[index - self.params.n] -= a * b
                else:
                    out[index] += a * b
        return RingElement.from_coeffs(out, self.params)

    def encode(self) -> bytes:
        width = (self.params.q.bit_length() + 7) // 8
        from .encoding import ring_parameters
        header = b"PQCT-RING-V2" + ring_parameters(
            self.params.n, self.params.q, self.params.k
        )
        return header + b"".join(c.to_bytes(width, "big") for c in self.coeffs)

    def _same_params(self, other: "RingElement") -> None:
        if self.params != other.params:
            raise ValueError("parameter mismatch")


@dataclass(frozen=True)
class Vector:
    """Fixed-length vector of ring elements."""

    elements: tuple[RingElement, ...]
    params: ToyParameters

    def __post_init__(self) -> None:
        if len(self.elements) != self.params.k:
            raise EncodingError("wrong vector length")
        if any(element.params != self.params for element in self.elements):
            raise EncodingError("vector parameter mismatch")

    @classmethod
    def from_rows(
        cls, rows: Sequence[Iterable[int]], params: ToyParameters
    ) -> "Vector":
        if len(rows) != params.k:
            raise EncodingError("wrong vector length")
        return cls(
            tuple(RingElement.from_coeffs(row, params) for row in rows), params
        )

    @classmethod
    def zero(cls, params: ToyParameters) -> "Vector":
        return cls((RingElement.zero(params),) * params.k, params)

    def add(self, other: "Vector") -> "Vector":
        self._same_params(other)
        return Vector(tuple(a.add(b) for a, b in zip(self.elements, other.elements)), self.params)

    def encode(self) -> bytes:
        return b"".join(element.encode() for element in self.elements)

    def _same_params(self, other: "Vector") -> None:
        if self.params != other.params:
            raise ValueError("parameter mismatch")


@dataclass(frozen=True)
class Matrix:
    """Fixed k-by-k matrix over the toy ring."""

    rows: tuple[tuple[RingElement, ...], ...]
    params: ToyParameters

    def __post_init__(self) -> None:
        if len(self.rows) != self.params.k or any(
            len(row) != self.params.k for row in self.rows
        ):
            raise EncodingError("wrong matrix dimensions")
        if any(element.params != self.params for row in self.rows for element in row):
            raise EncodingError("matrix parameter mismatch")

    def mul_vector(self, vector: Vector) -> Vector:
        if vector.params != self.params:
            raise ValueError("parameter mismatch")
        result = []
        for row in self.rows:
            acc = RingElement.zero(self.params)
            for coefficient, value in zip(row, vector.elements):
                acc = acc.add(coefficient.mul(value))
            result.append(acc)
        return Vector(tuple(result), self.params)

    def encode(self) -> bytes:
        return b"".join(element.encode() for row in self.rows for element in row)


@dataclass(frozen=True)
class Opening:
    """Opening for C = A*r + g*m."""

    randomness: Vector
    message: RingElement


def commit(
    matrix: Matrix,
    randomness: Vector,
    message: RingElement,
    generator: Vector,
) -> Vector:
    """Compute the toy additive commitment C = A*r + g*m."""
    if randomness.params != matrix.params or message.params != matrix.params:
        raise ValueError("parameter mismatch")
    if generator.params != matrix.params:
        raise ValueError("parameter mismatch")
    return matrix.mul_vector(randomness).add(
        Vector(tuple(g.scalar_mul(1).mul(message) for g in generator.elements), matrix.params)
    )


def open_commitment(
    matrix: Matrix, randomness: Vector, message: RingElement, generator: Vector
) -> tuple[Vector, Opening]:
    """Return a commitment and its opening for reference tests."""
    return commit(matrix, randomness, message, generator), Opening(randomness, message)


def verify_opening(
    commitment: Vector,
    opening: Opening,
    matrix: Matrix,
    generator: Vector,
) -> bool:
    """Verify an opening using exact canonical objects."""
    try:
        expected = commit(matrix, opening.randomness, opening.message, generator)
    except (EncodingError, ValueError):
        return False
    return expected == commitment


def hash_transcript(domain: bytes, *parts: bytes) -> bytes:
    """Hash a length-delimited, domain-separated transcript."""
    if not domain or len(domain) > 255:
        raise ValueError("domain must contain 1..255 bytes")
    digest = sha256()
    digest.update(b"PQCT-TRANSCRIPT-V1")
    digest.update(bytes((len(domain),)))
    digest.update(domain)
    for part in parts:
        if len(part) > 2**32 - 1:
            raise ValueError("transcript part too large")
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return digest.digest()
