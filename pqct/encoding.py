"""Bounded canonical integer/parameter encoding shared by transcripts and wire.

Version 2 is intentionally incompatible with the toy 32-bit-modulus encoding.
These are resource limits for the research implementation, not security claims.
"""

MAX_RING_DEGREE = 4096
MAX_MODULUS_BITS = 512
MAX_RING_ROWS = 64


def uint(value: int, width: int) -> bytes:
    if type(value) is not int or not 0 <= value < 1 << (8 * width):
        raise ValueError(f"expected uint{8 * width}")
    return value.to_bytes(width, "big")


def bigint(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 1 << MAX_MODULUS_BITS:
        raise ValueError("integer outside bounded encoding")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return uint(len(raw), 1) + raw


def ring_parameters(n: int, q: int, k: int) -> bytes:
    if not 1 <= n <= MAX_RING_DEGREE or not 1 <= k <= MAX_RING_ROWS or q <= 1:
        raise ValueError("ring parameters outside bounded encoding")
    return uint(n, 4) + bigint(q) + uint(k, 4)
