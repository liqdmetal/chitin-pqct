"""Reference HMC commitment from Gao et al. Section 2.2.

The construction is implemented over the lab's toy negacyclic ring so its
shape and algebra can be tested independently of the proof transcript. It is
not parameterized for security and must not be used for money, keys, or
consensus.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .ring_commitment import EncodingError, RingElement, ToyParameters
from .encoding import ring_parameters, uint


class HMCError(ValueError):
    """Raised when an HMC key, message, or opening is malformed."""


def _matrix_shape(matrix: Sequence[Sequence[RingElement]]) -> tuple[int, int]:
    rows = tuple(tuple(row) for row in matrix)
    if not rows or not rows[0]:
        raise HMCError("matrix must be nonempty")
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise HMCError("matrix rows must have equal width")
    return len(rows), width


def _check_matrix(
    matrix: Sequence[Sequence[RingElement]],
    params: ToyParameters,
) -> tuple[tuple[RingElement, ...], ...]:
    rows = tuple(tuple(row) for row in matrix)
    _matrix_shape(rows)
    if any(element.params != params for row in rows for element in row):
        raise HMCError("matrix parameter mismatch")
    return rows


def _mat_vec(
    matrix: Sequence[Sequence[RingElement]],
    vector: Sequence[RingElement],
) -> tuple[RingElement, ...]:
    if any(len(row) != len(vector) for row in matrix):
        raise HMCError("matrix/vector dimensions differ")
    params = vector[0].params if vector else None
    result: list[RingElement] = []
    for row in matrix:
        acc = RingElement.zero(params)  # type: ignore[arg-type]
        for coefficient, value in zip(row, vector):
            acc = acc.add(coefficient.mul(value))
        result.append(acc)
    return tuple(result)


def _add_vectors(
    left: Sequence[RingElement], right: Sequence[RingElement]
) -> tuple[RingElement, ...]:
    if len(left) != len(right):
        raise HMCError("vector dimensions differ")
    return tuple(a.add(b) for a, b in zip(left, right))


def centered_coefficients(element: RingElement) -> tuple[int, ...]:
    """Return coefficients in the paper's centered representative range."""
    q = element.params.q
    half = q // 2
    return tuple(value if value <= half else value - q for value in element.coeffs)


def infinity_norm(elements: Iterable[RingElement]) -> int:
    values = [abs(coefficient) for element in elements for coefficient in centered_coefficients(element)]
    return max(values, default=0)


@dataclass(frozen=True)
class HMCKey:
    """HMC public key ck = (G_r, G_m) with G_r in R_q^(n x m)."""

    G_r: tuple[tuple[RingElement, ...], ...]
    G_m: tuple[tuple[RingElement, ...], ...]
    params: ToyParameters

    def __post_init__(self) -> None:
        gr = _check_matrix(self.G_r, self.params)
        gm = _check_matrix(self.G_m, self.params)
        if len(gr) != len(gm):
            raise HMCError("G_r and G_m must have equal row count")
        object.__setattr__(self, "G_r", gr)
        object.__setattr__(self, "G_m", gm)

    @property
    def ring_rows(self) -> int:
        return len(self.G_r)

    @property
    def randomness_width(self) -> int:
        return len(self.G_r[0])

    @property
    def message_width(self) -> int:
        return len(self.G_m[0])

    def commit(
        self,
        message: Sequence[RingElement],
        randomness: Sequence[RingElement],
    ) -> tuple[RingElement, ...]:
        if len(message) != self.message_width:
            raise HMCError("message width mismatch")
        if len(randomness) != self.randomness_width:
            raise HMCError("randomness width mismatch")
        if any(value.params != self.params for value in (*message, *randomness)):
            raise HMCError("opening parameter mismatch")
        return _add_vectors(_mat_vec(self.G_r, randomness), _mat_vec(self.G_m, message))

    def encode(self) -> bytes:
        width = (self.params.q.bit_length() + 7) // 8
        header = (
            b"PQCT-HMC-V2"
            + ring_parameters(self.params.n, self.params.q, self.params.k)
            + uint(self.ring_rows, 4)
            + uint(self.randomness_width, 4)
            + uint(self.message_width, 4)
        )
        return header + b"".join(
            element.coeffs[index].to_bytes(width, "big")
            for matrix in (self.G_r, self.G_m)
            for row in matrix
            for element in row
            for index in range(self.params.n)
        )


def verify_opening(
    key: HMCKey,
    commitment: Sequence[RingElement],
    message: Sequence[RingElement],
    randomness: Sequence[RingElement],
) -> bool:
    """Verify C = G_r r + G_m m."""
    try:
        if len(commitment) != key.ring_rows:
            return False
        if any(element.params != key.params for element in commitment):
            return False
        return key.commit(message, randomness) == tuple(commitment)
    except (HMCError, EncodingError, TypeError, ValueError):
        return False


def verify_relaxed_opening(
    key: HMCKey,
    commitment: Sequence[RingElement],
    relaxation: RingElement,
    message: Sequence[RingElement],
    randomness: Sequence[RingElement],
) -> bool:
    """Verify y*C = Com(m; r), the paper's relaxed opening boundary."""
    try:
        if relaxation.params != key.params or len(commitment) != key.ring_rows:
            return False
        scaled = tuple(relaxation.mul(element) for element in commitment)
        return key.commit(message, randomness) == scaled
    except (HMCError, EncodingError, TypeError, ValueError):
        return False


def bounded_ring_element(values: Iterable[int], params: ToyParameters) -> RingElement:
    """Create a ring element from a small centered coefficient vector."""
    values = tuple(int(value) for value in values)
    if len(values) != params.n:
        raise HMCError("coefficient width mismatch")
    return RingElement.from_coeffs(values, params)
