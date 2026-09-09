"""Balance-conservation composition oracle (Gao Section 4).

Wires amount decomposition + Protocol 1 bit commitments + cycle masking
into an executable conservation check. Reference oracle only, not a
complete lattice balance proof (no rejection/soundness proof)."""

from __future__ import annotations

from dataclasses import dataclass

from .cycle_masking import CycleMask, derive_cycle_mask, relation_response_is_exactly_zero
from .relations import decompose_unsigned


class BalanceCompositionError(ValueError):
    """Malformed balance-composition input."""


@dataclass(frozen=True)
class SignedAmount:
    """One amount with its conservation sign (+1 credit, -1 debit)."""

    value: int
    sign: int


@dataclass(frozen=True)
class BalanceColumns:
    """Per-column weighted sums c_j = sum(sign_i * bit(amount_i, j))."""

    amounts: tuple[SignedAmount, ...]
    bit_width: int
    columns: tuple[int, ...]
    weighted_sum: int
    conserved: bool


def build_balance_columns(
    amounts: tuple[SignedAmount, ...],
    bit_width: int,
) -> BalanceColumns:
    """Decompose signed amounts and compute the per-column conservation.

    Matches Gao eq.(14): c_j = sum_i lambda_i * b_{i,j} where lambda_i is
    the amount sign and b_{i,j} is bit j of amount i. Conservation holds
    iff sum_j 2^j * c_j == 0 (the exact integer relation, not mod q).
    """
    if bit_width <= 0:
        raise BalanceCompositionError("bit width must be positive")
    if not amounts:
        raise BalanceCompositionError("amount set cannot be empty")
    for amount in amounts:
        if amount.sign not in (-1, 1):
            raise BalanceCompositionError("amount sign must be +1 or -1")
        try:
            decompose_unsigned(amount.value, bit_width)  # range check
        except ValueError as error:
            raise BalanceCompositionError(
                f"amount {amount.value} outside {bit_width}-bit range"
            ) from error
    values = tuple(amount.value for amount in amounts)
    signs = tuple(amount.sign for amount in amounts)
    # c_j = sum_i sign_i * bit(value_i, j), one sum per bit column j.
    # This must NOT zip signs (per-amount) against columns (per-bit) --
    # that silently truncates to min(len) and gives a wrong relation.
    bits = tuple(decompose_unsigned(value, bit_width) for value in values)
    cols = tuple(
        sum(sign * bits[i][j] for i, sign in enumerate(signs))
        for j in range(bit_width)
    )
    weighted = sum((1 << index) * col for index, col in enumerate(cols))
    return BalanceColumns(
        amounts=amounts,
        bit_width=bit_width,
        columns=cols,
        weighted_sum=weighted,
        conserved=weighted == 0,
    )


@dataclass(frozen=True)
class MaskedBalanceResponse:
    """Masked response f = x*c + d for a balance column, exact-integer."""

    challenge: int
    columns: tuple[int, ...]
    mask: CycleMask
    response: tuple[int, ...]
    weighted_response: int
    response_relation_exact: bool


def build_masked_balance_response(
    columns: tuple[int, ...],
    challenge: int,
    sampled_mask: tuple[int, ...],
) -> MaskedBalanceResponse:
    """Mask the balance columns so the weighted response is exactly zero.

    Uses the cycle-masking identity (Gao eq.15 / Protocol 2): d is chosen
    with sum_j 2^j d_j = 0, so sum_j 2^j (x*c_j + d_j) stays zero over the
    INTEGERS even when individual terms overflow q -- avoiding the
    small-q soundness error the paper highlights in eq.(15) discussion.
    """
    if challenge <= 0:
        raise BalanceCompositionError("challenge must be positive")
    mask = derive_cycle_mask(sampled_mask)
    if len(columns) != len(mask.values):
        raise BalanceCompositionError("column/mask dimension mismatch")
    response = tuple(
        challenge * column + value
        for column, value in zip(columns, mask.values)
    )
    weighted = sum((1 << index) * value for index, value in enumerate(response))
    return MaskedBalanceResponse(
        challenge=challenge,
        columns=columns,
        mask=mask,
        response=response,
        weighted_response=weighted,
        response_relation_exact=weighted == 0,
    )


__all__ = [
    "BalanceColumns",
    "BalanceCompositionError",
    "MaskedBalanceResponse",
    "SignedAmount",
    "build_balance_columns",
    "build_masked_balance_response",
]

