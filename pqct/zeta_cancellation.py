"""Attacking the non-adaptive zeta proposal, rather than leaving it open.

THE QUESTION LEFT OPEN
----------------------
`nonadaptive_zeta.py` proposes deriving zeta from the STATEMENT alone
instead of from the commitments, collapsing the protocol from two
Fiat-Shamir challenges to one and recovering 320 bits of forking/QROM loss.
It demonstrated the mechanical part (20 commitment variants -> 20 distinct
zetas before, -> 1 after) but left the soundness question open with two
competing arguments:

  might be fine  -- commitments are bound into the statement, so choosing
                    them changes zeta; grinding becomes hash inversion.
  might not be   -- an adversary can fix a statement, READ zeta, then
                    search the remaining freedom (openings, masks) for a
                    cross-account cancellation.

The second branch is testable. This module tests it.

THE ATTACK, CONCRETELY
----------------------
Protocol 1 aggregates S accounts with weights zeta^i. The soundness worry
is that a prover who knows the weights in advance can choose per-account
values that individually violate the relation but cancel in the aggregate:

    sum_i zeta^i * (bad_i) = 0

With random zeta this requires guessing; with known zeta it becomes solving
a linear equation over R_q, which is easy IF the prover has enough free
choice in the bad_i.

So the attack is: given a known zeta, find nonzero deviations d_0..d_{S-1},
each SMALL enough to pass the verifier's norm gates, with
sum_i zeta^i d_i = 0. If such deviations exist, the aggregate check passes
while individual accounts are wrong.

WHAT THE RESULT MEANS
---------------------
Finding small cancelling deviations does NOT by itself break the protocol:
the per-account binary/E-F commitment equations must also be satisfied, and
those are checked against commitments the prover already published. What it
WOULD show is that the aggregate check contributes no soundness once zeta
is known, i.e. the security rests entirely on the per-account equations --
which is a materially weaker statement than the paper's, and exactly what a
reviewer needs to know before the 320-bit saving is banked.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hmc import bounded_ring_element, centered_coefficients
from .ring_commitment import RingElement, ToyParameters


class CancellationError(ValueError):
    """Malformed cancellation-search input."""


@dataclass(frozen=True)
class CancellationResult:
    """Whether small cancelling deviations were found for a known zeta."""

    accounts: int
    zeta_known: bool
    found: bool
    deviations: tuple
    max_coefficient: int
    norm_budget: int

    @property
    def within_budget(self) -> bool:
        return self.max_coefficient <= self.norm_budget

    @property
    def exploitable(self) -> bool:
        """A cancellation only matters if it also passes the norm gates."""
        return self.found and self.within_budget

    def summary(self) -> dict:
        return {
            "accounts": self.accounts,
            "zeta_known": self.zeta_known,
            "found_cancellation": self.found,
            "max_coefficient": self.max_coefficient,
            "norm_budget": self.norm_budget,
            "within_norm_budget": self.within_budget,
            "exploitable": self.exploitable,
            "verdict": (
                "AGGREGATE CHECK CONTRIBUTES NO SOUNDNESS once zeta is "
                "known: small deviations cancel in the aggregate, so "
                "security rests entirely on the per-account equations"
                if self.exploitable else
                "no small cancellation found by this search; the aggregate "
                "check retains some soundness even with zeta known "
                "(NOT a proof -- absence of a found attack is not security)"
            ),
        }


def trivial_cancellation(zeta: RingElement, accounts: int,
                         norm_budget: int = 1) -> CancellationResult:
    """The simplest cancellation: alternating deviations for S = 2.

    For two accounts the aggregate is d_0 + zeta*d_1. Choosing
    d_1 = 0 and d_0 = 0 is the trivial zero solution and proves nothing, so
    the search is for NONZERO deviations.

    For S = 2 a nonzero cancellation needs d_0 = -zeta*d_1. That is
    computable directly -- no search required -- but the product zeta*d_1
    is generally NOT small: multiplying by a sparse challenge with
    coefficients +-p inflates the norm by roughly p*w. So the interesting
    question is not whether a cancellation EXISTS (it always does) but
    whether one exists inside the verifier's norm budget.
    """
    if accounts < 2:
        raise CancellationError("need at least two accounts to cancel")
    params = zeta.params

    # Smallest possible nonzero deviation on the second account.
    unit = bounded_ring_element((1,) + (0,) * (params.n - 1), params)
    # Forced value on the first account.
    forced = zeta.mul(unit).scalar_mul(-1)

    deviations = (forced, unit) + tuple(
        RingElement.zero(params) for _ in range(accounts - 2)
    )

    # Verify it really cancels: d_0 + zeta*d_1 + zeta^2*d_2 + ...
    total = RingElement.zero(params)
    power = bounded_ring_element((1,) + (0,) * (params.n - 1), params)
    for deviation in deviations:
        total = total.add(power.mul(deviation))
        power = power.mul(zeta)
    cancels = all(value == 0 for value in total.coeffs)

    largest = max(
        (max((abs(c) for c in centered_coefficients(d)), default=0)
         for d in deviations),
        default=0,
    )

    return CancellationResult(
        accounts=accounts,
        zeta_known=True,
        found=cancels,
        deviations=deviations,
        max_coefficient=largest,
        norm_budget=norm_budget,
    )


def norm_inflation_factor(zeta: RingElement) -> dict:
    """How much does multiplying by zeta inflate a unit deviation?

    This is the quantity that decides the attack. A sparse challenge with w
    nonzero coefficients of magnitude p inflates an infinity-norm-1 input
    to roughly p (per coefficient) and its L2 norm by ~p*sqrt(w). If the
    verifier's budget is far below that, forced cancellations are always
    out of bounds and the aggregate check keeps its soundness even with
    zeta public.
    """
    params = zeta.params
    unit = bounded_ring_element((1,) + (0,) * (params.n - 1), params)
    product = zeta.mul(unit)
    zeta_coeffs = centered_coefficients(zeta)
    product_coeffs = centered_coefficients(product)

    nonzero = sum(1 for c in zeta_coeffs if c != 0)
    peak = max((abs(c) for c in zeta_coeffs), default=0)

    return {
        "zeta_nonzero_coefficients": nonzero,
        "zeta_peak_coefficient": peak,
        "unit_infinity_norm": 1,
        "product_infinity_norm": max(
            (abs(c) for c in product_coeffs), default=0
        ),
        "inflation": max((abs(c) for c in product_coeffs), default=0),
        "interpretation": (
            "a forced cancellation d_0 = -zeta*d_1 inflates the deviation "
            "by the challenge's peak coefficient, so with a small verifier "
            "norm budget the forced value is REJECTED by the norm gate even "
            "though it cancels algebraically"
        ),
    }


def assessment(zeta: RingElement, norm_budget: int = 1) -> dict:
    """Combine the search and the inflation bound into one finding."""
    result = trivial_cancellation(zeta, accounts=2, norm_budget=norm_budget)
    inflation = norm_inflation_factor(zeta)

    return {
        "cancellation": result.summary(),
        "inflation": inflation,
        "finding": (
            "Cancellations always EXIST for known zeta (solve "
            "d_0 = -zeta*d_1), so the question is purely whether one fits "
            "inside the verifier's norm budget. Multiplying by a sparse "
            f"challenge inflates an infinity-norm-1 deviation to "
            f"{inflation['product_infinity_norm']}, versus a budget of "
            f"{norm_budget}. On this instance the forced deviation is "
            + ("WITHIN budget, so the aggregate check adds no soundness."
               if result.exploitable else
               "OUTSIDE budget, so the norm gate blocks the cheapest "
               "cancellation.")
        ),
        "residual_gap": (
            "This tests only the CHEAPEST cancellation (unit deviation on "
            "one account). A real analysis must bound ALL small-norm "
            "solutions of sum_i zeta^i d_i = 0, which is a lattice problem "
            "in its own right -- the ideal generated by the challenge. That "
            "is the actual open question and it still needs a cryptographer."
        ),
        "status": "NARROWED, not closed",
    }


__all__ = [
    "CancellationError",
    "CancellationResult",
    "assessment",
    "norm_inflation_factor",
    "trivial_cancellation",
]
