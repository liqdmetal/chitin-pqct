"""Canonical wire encoding for PQ-CT transactions (Chitin).

A network needs a BYTE FORMAT before it needs a node. This module is that
format, and it is written to be hostile to malleability: every decode
re-derives structure from an explicit header and REJECTS anything it did not
itself produce. Round-trip equality is not sufficient -- a codec that accepts
two distinct byte strings for one transaction hands an attacker a way to
mutate a txid without changing the proof.

Design rules
------------
1. CANONICAL: coefficients are stored reduced into [0, q) with a fixed width
   derived from q. A coefficient byte-group whose value is >= q is REJECTED
   rather than silently reduced -- otherwise c and c+q encode "the same"
   element and the txid becomes malleable.
2. EXPLICIT: every variable-length run is length-prefixed. No trailing-data
   tolerance: leftover bytes are an error.
3. SELF-DESCRIBING PARAMS: n and q ride in the header at full width (q as a
   length-prefixed big-endian integer, NOT the 4 bytes that
   RingElement.encode uses -- that overflows for the paper's q = 2^49).
4. VERSIONED + DOMAIN-SEPARATED: the magic string carries a version and the
   word EXPERIMENTAL, so these bytes can never be confused with a production
   format.

What this module deliberately does NOT do: claim the encoded proof is sound.
It is a faithful byte representation of a research construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hmc import HMCError
from .ring_commitment import RingElement, ToyParameters

MAGIC = b"CHITIN-TX-EXPERIMENTAL-V1"


class CodecError(ValueError):
    """Raised when bytes are not a canonical encoding."""


def _coeff_width(q: int) -> int:
    return (q.bit_length() + 7) // 8


def _put_uint(value: int, width: int) -> bytes:
    if value < 0:
        raise CodecError("negative value in unsigned field")
    try:
        return int(value).to_bytes(width, "big")
    except OverflowError as error:
        raise CodecError(f"value {value} exceeds {width}-byte field") from error


def _put_bigint(value: int) -> bytes:
    """Length-prefixed big-endian integer (no 4-byte q limit)."""
    if value < 0:
        raise CodecError("negative bigint")
    if value == 0:
        return b"\x00"
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if len(raw) > 255:
        raise CodecError("bigint too large")
    return bytes((len(raw),)) + raw


class _Reader:
    """Strict cursor: every read is bounds-checked, no silent truncation."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        if count < 0:
            raise CodecError("negative read length")
        end = self.pos + count
        if end > len(self.data):
            raise CodecError("truncated encoding")
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def uint(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def bigint(self) -> int:
        length = self.uint(1)
        if length == 0:
            return 0
        return int.from_bytes(self.take(length), "big")

    def finish(self) -> None:
        if self.pos != len(self.data):
            raise CodecError(
                f"trailing data: {len(self.data) - self.pos} unconsumed bytes"
            )


def encode_params(params: ToyParameters) -> bytes:
    return _put_uint(params.n, 4) + _put_bigint(params.q) + _put_uint(params.k, 4)


def decode_params(reader: _Reader) -> ToyParameters:
    n = reader.uint(4)
    q = reader.bigint()
    k = reader.uint(4)
    if n <= 0 or q <= 1 or k <= 0:
        raise CodecError("invalid ring parameters")
    return ToyParameters(n=n, q=q, k=k)


def encode_element(element: RingElement) -> bytes:
    """Coefficients only; params ride once in the transaction header."""
    width = _coeff_width(element.params.q)
    q = element.params.q
    out = bytearray()
    for coefficient in element.coeffs:
        value = int(coefficient)
        if not 0 <= value < q:
            raise CodecError(
                f"non-canonical coefficient {value} outside [0,{q}) -- refusing "
                "to encode a malleable representation"
            )
        out += _put_uint(value, width)
    return bytes(out)


def decode_element(reader: _Reader, params: ToyParameters) -> RingElement:
    width = _coeff_width(params.q)
    coeffs = []
    for _ in range(params.n):
        value = reader.uint(width)
        if value >= params.q:
            raise CodecError(
                f"non-canonical coefficient {value} >= q={params.q}; "
                "c and c+q must not both decode"
            )
        coeffs.append(value)
    return RingElement(coeffs=tuple(coeffs), params=params)


def encode_vector(elements) -> bytes:
    items = tuple(elements)
    out = _put_uint(len(items), 4)
    for element in items:
        out += encode_element(element)
    return out


def decode_vector(reader: _Reader, params: ToyParameters) -> tuple[RingElement, ...]:
    count = reader.uint(4)
    if count > 1_000_000:
        raise CodecError("implausible vector length")
    return tuple(decode_element(reader, params) for _ in range(count))


def encode_matrix(rows) -> bytes:
    items = tuple(tuple(row) for row in rows)
    out = _put_uint(len(items), 4)
    for row in items:
        out += encode_vector(row)
    return out


def decode_matrix(reader: _Reader, params: ToyParameters):
    count = reader.uint(4)
    if count > 1_000_000:
        raise CodecError("implausible matrix row count")
    return tuple(decode_vector(reader, params) for _ in range(count))


__all__ = [
    "MAGIC",
    "CodecError",
    "decode_element",
    "decode_matrix",
    "decode_params",
    "decode_vector",
    "encode_element",
    "encode_matrix",
    "encode_params",
    "encode_vector",
]
