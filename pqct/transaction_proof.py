"""Transaction proof: Protocol 1 (binary) + Protocol 5 (conservation) composed.

One shared set of HMC bit commitments B_i serves BOTH halves:
per-amount Protocol 1 sampled proofs (the bits are binary) and one
Protocol 5 linear-equation proof (sum_i lambda_i * a_i = 0 over Z,
mod-q cheats rejected by the f_0 range gate). The verifier re-checks
that Protocol 5 used the SAME commitments as the binary proofs.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Sequence

from .balance_composition import SignedAmount
from .binary_protocol1_ring import RingProtocol1Parameters, verify_protocol1_ring
from .hmc import HMCKey
from .protocol1_sampled import SampledProtocol1Result, prove_protocol1_ring_sampled
from .protocol1_sampling import Protocol1DistributionParameters
from .protocol5 import Protocol5Parameters, Protocol5Result
from .protocol5 import prove_linear_equation, verify_linear_equation
from .ring_commitment import RingElement


class TransactionProofError(ValueError):
    """Malformed transaction proof input or failed composition check."""


@dataclass(frozen=True)
class TransactionProof:
    """Composed transaction artifact: shared commitments + both proof halves."""

    bit_width: int
    amounts: tuple[SignedAmount, ...]
    bit_commitments: tuple[tuple[RingElement, ...], ...]
    binary_proofs: tuple[SampledProtocol1Result, ...]
    conservation: Protocol5Result
    shared_commitments_ok: bool
    binary_ok: bool
    conservation_ok: bool

    @property
    def accepted(self) -> bool:
        return self.shared_commitments_ok and self.binary_ok and self.conservation_ok


def _constant_poly(value: int, params) -> RingElement:
    return RingElement.from_coeffs((value,) + (0,) * (params.n - 1), params)


def prove_transaction(
    *,
    seed: bytes,
    statement: bytes,
    key: HMCKey,
    amounts: Sequence[SignedAmount],
    bit_width: int,
    distribution: Protocol1DistributionParameters,
    p1_params: RingProtocol1Parameters,
    p5: Protocol5Parameters,
    phi2: Decimal,
    phi3: Decimal,
    p1_max_attempts: int = 512,
    p5_max_attempts: int = 512,
) -> TransactionProof:
    """Prove one transaction: bits binary (P1 per amount) + conserved (P5).

    Both halves run over ONE shared set of commitments/openings sampled
    up-front here; Protocol 5 receives them via openings_override so it
    cannot commit to different bits than the Protocol 1 proofs cover.
    The composed verifier checks that identity explicitly.
    """
    if not seed or not statement:
        raise TransactionProofError("seed and statement cannot be empty")
    signed = tuple(amounts)
    if not signed:
        raise TransactionProofError("amount set cannot be empty")
    if bit_width != key.message_width or bit_width != p5.k:
        raise TransactionProofError("bit width must equal HMC message width and k")
    params = key.params

    # Fail fast: a non-conserved transaction can never yield an accepted
    # Protocol 5 proof (that IS the soundness property), so refuse before
    # burning the full retry budget on an impossible goal.
    from .balance_composition import BalanceCompositionError, build_balance_columns
    try:
        columns = build_balance_columns(signed, bit_width)
    except BalanceCompositionError as error:
        raise TransactionProofError(str(error)) from error
    if not columns.conserved:
        raise TransactionProofError(
            "transaction is not conserved over the integers "
            f"(sum_j 2^j c_j = {columns.weighted_sum} != 0); "
            "no Protocol 5 proof can exist for it"
        )

    from .protocol1_sampling import XofByteSource, sample_box_ring_vector
    from .relations import decompose_unsigned

    try:
        openings = tuple(
            sample_box_ring_vector(
                XofByteSource(seed + b"|rb|" + index.to_bytes(4, "big")),
                params, p5.m, p5.B,
            )
            for index in range(len(signed))
        )
        bits_rows = tuple(
            tuple(
                _constant_poly(bit, params)
                for bit in decompose_unsigned(amount.value, bit_width)
            )
            for amount in signed
        )
        commitments = tuple(
            key.commit(bits, opening)
            for bits, opening in zip(bits_rows, openings)
        )
    except (TypeError, ValueError) as error:
        raise TransactionProofError(f"amount decomposition failed: {error}") from error

    binary_proofs = []
    for index in range(len(signed)):
        try:
            result = prove_protocol1_ring_sampled(
                seed + b"|p1|" + index.to_bytes(4, "big"),
                statement + b"|amount|" + index.to_bytes(4, "big"),
                key, key, key, key,
                (commitments[index],), (bits_rows[index],), (openings[index],),
                p5.p, p5.w, distribution, p1_params,
                max_attempts=p1_max_attempts,
            )
        except (TypeError, ValueError) as error:
            raise TransactionProofError(
                f"Protocol 1 proof for amount {index} failed: {error}"
            ) from error
        binary_proofs.append(result)

    try:
        conservation = prove_linear_equation(
            seed=seed + b"|p5",
            statement=statement + b"|conservation",
            key=key,
            amounts=signed,
            bit_width=bit_width,
            p5=p5,
            phi2=phi2,
            phi3=phi3,
            max_attempts=p5_max_attempts,
            openings_override=openings,
        )
    except (TypeError, ValueError) as error:
        raise TransactionProofError(
            f"Protocol 5 conservation proof failed: {error}"
        ) from error

    shared_ok = conservation.bit_commitments == commitments
    binary_ok = all(
        verify_protocol1_ring(
            statement + b"|amount|" + index.to_bytes(4, "big"),
            key, key, key, key,
            (commitments[index],),
            proof.proof,
            p1_params,
        )
        for index, proof in enumerate(binary_proofs)
    )
    p5_verification = verify_linear_equation(
        statement=statement + b"|conservation", key_c=key,
        bit_commitments=conservation.bit_commitments,
        lambdas=conservation.lambdas,
        proof=conservation.proof, p5=p5,
    )
    conservation_ok = p5_verification.accepted and conservation.conserved

    return TransactionProof(
        bit_width=bit_width,
        amounts=signed,
        bit_commitments=commitments,
        binary_proofs=tuple(binary_proofs),
        conservation=conservation,
        shared_commitments_ok=shared_ok,
        binary_ok=binary_ok,
        conservation_ok=conservation_ok,
    )


__all__ = ["TransactionProof", "TransactionProofError", "prove_transaction"]

