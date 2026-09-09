"""Lattice balance transcript: amount bits -> HMC -> Protocol 1 composition.

Wires pqct.balance_composition's integer oracle to real protocol objects:
per-amount HMC bit commitments, sampled Protocol 1 binary proofs with
rejection gating, the eq.(11) homomorphic combination check, and the
exact-integer conservation relation. Research oracle; the conservation
equation itself is checked at integer level against the witnesses, NOT
yet proven in zero knowledge (that is Protocol 5's inner-product
argument, still unimplemented).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .balance_composition import (
    BalanceColumns,
    BalanceCompositionError,
    SignedAmount,
    build_balance_columns,
)
from .binary_protocol1_ring import RingProtocol1Parameters
from .hmc import HMCError, HMCKey, bounded_ring_element
from .protocol1_sampled import (
    SampledProtocol1Error,
    SampledProtocol1Result,
    prove_protocol1_ring_sampled,
)
from .protocol1_sampling import (
    Protocol1DistributionParameters,
    SamplingError,
    XofByteSource,
    sample_box_ring_vector,
)
from .ring_commitment import RingElement


class BalanceTranscriptError(ValueError):
    """Malformed balance-transcript input or a failed composition check."""


@dataclass(frozen=True)
class AmountCommitment:
    """One amount's bit vector, opening, HMC commitment, and binary proof."""

    amount: SignedAmount
    bits: tuple[RingElement, ...]
    opening: tuple[RingElement, ...]
    commitment: tuple[RingElement, ...]
    proof: SampledProtocol1Result


@dataclass(frozen=True)
class BalanceTranscript:
    """Composed lattice balance artifact with explicit check flags."""

    bit_width: int
    amounts: tuple[AmountCommitment, ...]
    columns: BalanceColumns
    combined_commitment: tuple[RingElement, ...]
    combined_randomness: tuple[RingElement, ...]
    combination_opening_ok: bool
    conservation_exact: bool

    @property
    def all_ok(self) -> bool:
        return self.combination_opening_ok and self.conservation_exact


def _amount_bits_ring(
    amount: SignedAmount, bit_width: int, params,
) -> tuple[RingElement, ...]:
    from .relations import decompose_unsigned

    try:
        bits = decompose_unsigned(amount.value, bit_width)
    except (TypeError, ValueError) as error:
        raise BalanceTranscriptError(str(error)) from error
    return tuple(
        bounded_ring_element((bit,) + (0,) * (params.n - 1), params) for bit in bits
    )


def build_balance_transcript(
    *,
    seed: bytes,
    statement: bytes,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    amounts: Sequence[SignedAmount],
    bit_width: int,
    p: int,
    w: int,
    distribution: Protocol1DistributionParameters,
    params: RingProtocol1Parameters,
    max_attempts: int = 512,
) -> BalanceTranscript:
    """Commit each amount's bits, prove them binary, combine via eq.(11).

    Each amount gets its OWN Protocol 1 binary proof (the parameter
    object caps max_vectors <= 2, so multi-amount batching is not used).
    The homomorphic combination
        C_c = sum_i sign_i * B_i = Com(c; sum_i sign_i * r_{b,i})
    is Gao eq.(11): the verifier computes the c-commitment locally.
    Conservation itself is checked as the exact integer relation
    sum_j 2^j c_j == 0 -- at integer level against the witnesses, not
    yet as a zero-knowledge Protocol 5 inner-product argument.
    """
    if not seed or not statement:
        raise BalanceTranscriptError("seed and statement cannot be empty")
    if not amounts:
        raise BalanceTranscriptError("amount set cannot be empty")
    if bit_width != base_key.message_width:
        raise BalanceTranscriptError("bit width must equal HMC message width")
    try:
        columns = build_balance_columns(tuple(amounts), bit_width)
    except BalanceCompositionError as error:
        raise BalanceTranscriptError(str(error)) from error
    if params.max_vectors < 1:
        raise BalanceTranscriptError("proof parameters must allow one vector")

    committed: list[AmountCommitment] = []
    try:
        for index, amount in enumerate(amounts):
            bits = _amount_bits_ring(amount, bit_width, base_key.params)
            opening = sample_box_ring_vector(
                XofByteSource(
                    seed + b"|opening|" + index.to_bytes(4, "big")
                ),
                base_key.params,
                base_key.randomness_width,
                distribution.B,
            )
            commitment = base_key.commit(bits, opening)
            proof = prove_protocol1_ring_sampled(
                seed + b"|proof|" + index.to_bytes(4, "big"),
                statement + b"|amount|" + index.to_bytes(4, "big"),
                base_key, key_e, key_f, key_g,
                (commitment,), (bits,), (opening,),
                p, w, distribution, params,
                max_attempts=max_attempts,
            )
            committed.append(AmountCommitment(amount, bits, opening, commitment, proof))
    except (SampledProtocol1Error, SamplingError, HMCError, TypeError, ValueError) as error:
        raise BalanceTranscriptError(f"amount proof failed: {error}") from error

    params_ring = base_key.params
    zero_rows = tuple(RingElement.zero(params_ring) for _ in range(base_key.ring_rows))
    combined = tuple(zero_rows)
    combined_randomness = tuple(
        RingElement.zero(params_ring) for _ in range(base_key.randomness_width)
    )
    for entry in committed:
        sign = entry.amount.sign
        combined = tuple(
            total.add(value.scalar_mul(sign))
            for total, value in zip(combined, entry.commitment)
        )
        combined_randomness = tuple(
            total.add(value.scalar_mul(sign))
            for total, value in zip(combined_randomness, entry.opening)
        )

    column_elements = tuple(
        bounded_ring_element((value,) + (0,) * (params_ring.n - 1), params_ring)
        for value in columns.columns
    )
    try:
        combination_opening_ok = (
            base_key.commit(column_elements, combined_randomness) == combined
        )
    except (HMCError, TypeError, ValueError):
        combination_opening_ok = False

    return BalanceTranscript(
        bit_width=bit_width,
        amounts=tuple(committed),
        columns=columns,
        combined_commitment=combined,
        combined_randomness=combined_randomness,
        combination_opening_ok=combination_opening_ok,
        conservation_exact=columns.conserved,
    )


__all__ = [
    "AmountCommitment",
    "BalanceTranscript",
    "BalanceTranscriptError",
    "build_balance_transcript",
]

