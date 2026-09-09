"""Mixed per-column bound M-SIS: bracketing the approximation error.

THE PROBLEM
-----------
`pqct/msis_hardness.py` and the lattice-estimator bridge both feed a SINGLE
scalar norm bound to an M-SIS instance. The real instance from HMC binding
is not like that. A collision gives

    G * (dm, dr) = 0   with   dm = m1 - m0,  dr = r1 - r0

and the two blocks have very different bounds:

  * dm spans v = k = 64 MESSAGE columns. For bit commitments each m_i is a
    bit, so dm has entries in {-1, 0, 1}.
  * dr spans m = 60 RANDOMNESS columns with r sampled from {-B..B}, so dr
    has entries bounded by 2B = 2.

Meanwhile gamma_bin ~ 1.43e14 is the RELAXED-opening bound that Protocol 1's
extractor produces, which is enormous by comparison. Feeding one scalar
forces a choice between:

    uniform-tight  : bound = 2   on every column
                     -> a MUCH harder instance than reality (the relaxed
                        openings genuinely can be large), so it OVERSTATES
                        security.
    uniform-relaxed: bound = 2*gamma_bin on every column
                     -> a MUCH easier instance than reality (the randomness
                        block is really tiny), so it UNDERSTATES security.

Neither is the truth, and the truth is not between them in any simple way,
because the two blocks contribute differently to the lattice volume.

WHAT THIS MODULE DOES
---------------------
It computes both extremes so the approximation error is BOUNDED rather than
unknown, using the standard volume/Gaussian-heuristic argument for a
block-bounded solution:

A solution with per-column bounds b_j exists (by counting) when the box
volume prod_j (2*b_j + 1) exceeds the number of lattice cosets q^(n*d).
Taking logs, define the SLACK

    slack = sum_j log2(2*b_j + 1) - n*d*log2(q).

slack > 0 means solutions are abundant by counting; slack < 0 means the box
is too small to be guaranteed a solution and the instance is meaningful.
This is a counting statement, NOT a cost statement -- the same distinction
that caused an earlier false alarm in this repo -- so the module reports it
as such and never converts slack into bits.

For the geometric-mean bound (the scalar an estimator would need to model
the same volume) it also reports

    equivalent_uniform_bound = ( prod_j (2 b_j + 1) )^(1/(total columns)) / 2

which is the single bound reproducing the true box volume. That is the most
defensible scalar substitute, and it is what a mixed-bound-aware estimate
would have to beat.

HONEST SCOPE
------------
This does not resolve item 3. Resolving it requires an estimator that
accepts per-block bounds (lattice-estimator does not) or a hand analysis of
the block structure by a lattice cryptographer. What it does is convert
"a single scalar cannot express it, unknown error" into an explicit interval
with a stated volume-equivalent midpoint.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .msis_hardness import HardnessError, analyze_msis


@dataclass(frozen=True)
class ColumnBlock:
    """A group of columns sharing one coefficient bound."""

    name: str
    columns: int
    bound: float
    rationale: str

    def __post_init__(self) -> None:
        if self.columns <= 0:
            raise HardnessError(f"{self.name}: column count must be positive")
        if self.bound <= 0:
            raise HardnessError(f"{self.name}: bound must be positive")

    @property
    def log2_box_volume(self) -> float:
        """log2 of (2*bound + 1)^columns -- the block's contribution."""
        return self.columns * math.log2(2.0 * self.bound + 1.0)


@dataclass(frozen=True)
class MixedBoundReport:
    """Both extremes plus the volume-equivalent scalar."""

    blocks: tuple
    n_int: int
    log2_q: float
    tight_bound: float
    relaxed_bound: float
    tight_verdict: str
    relaxed_verdict: str
    equivalent_uniform_bound: float
    slack_bits: float

    @property
    def total_columns(self) -> int:
        return sum(b.columns for b in self.blocks)

    @property
    def solutions_abundant_by_counting(self) -> bool:
        return self.slack_bits > 0.0

    @property
    def interval_description(self) -> str:
        return (
            f"the true instance sits between a uniform bound of "
            f"{self.tight_bound:g} (overstates security: {self.tight_verdict}) "
            f"and {self.relaxed_bound:.3e} (understates: "
            f"{self.relaxed_verdict})"
        )

    def summary(self) -> dict:
        return {
            "blocks": [
                {
                    "name": b.name,
                    "columns": b.columns,
                    "bound": b.bound,
                    "log2_box_volume": round(b.log2_box_volume, 1),
                    "rationale": b.rationale,
                }
                for b in self.blocks
            ],
            "total_columns": self.total_columns,
            "n_int": self.n_int,
            "tight_uniform_bound": self.tight_bound,
            "tight_verdict": self.tight_verdict,
            "relaxed_uniform_bound": f"{self.relaxed_bound:.3e}",
            "relaxed_verdict": self.relaxed_verdict,
            "equivalent_uniform_bound": round(self.equivalent_uniform_bound, 4),
            "slack_bits_counting": round(self.slack_bits, 1),
            "solutions_abundant_by_counting": self.solutions_abundant_by_counting,
            "interval": self.interval_description,
            "status": (
                "OPEN -- the interval is bounded but not narrowed. Needs an "
                "estimator supporting per-block bounds, or a hand analysis. "
                "slack_bits is a COUNTING statement and is deliberately not "
                "converted into bits of security."
            ),
        }


def analyze_mixed_bounds(*, blocks, n_module: int, d: int, q: int,
                         relaxed_bound: float) -> MixedBoundReport:
    """Bracket the mixed-bound instance between its two uniform extremes."""
    block_tuple = tuple(blocks)
    if not block_tuple:
        raise HardnessError("at least one column block is required")
    if min(n_module, d) <= 0 or q <= 1:
        raise HardnessError("invalid ring/modulus parameters")

    n_int = n_module * d
    log2_q = math.log2(q)
    total_columns = sum(b.columns for b in block_tuple)

    tight = max(b.bound for b in block_tuple)
    if tight <= 1.0:
        # log2(beta) <= 0 is outside required_root_hermite's domain (a
        # norm-1 vector is a trivial target), so no delta is defined.
        tight_verdict = (
            f"bound {tight:g} <= 1: a vector this short is a degenerate "
            "target and no root-Hermite factor is defined for it"
        )
    else:
        tight_report = analyze_msis(
            n_module=n_module, d=d, q=q, beta=tight
        )
        costs = [v for v in tight_report.costs_bits.values() if v is not None]
        if costs:
            tight_verdict = f"{min(costs):.0f}-{max(costs):.0f} bits"
        else:
            # No cost model resolves because the required delta is so close
            # to 1 that no bounded BKZ block size reaches it. That is not a
            # failure -- it means this extreme is astronomically hard, i.e.
            # far off the top of any cost model's scale.
            tight_verdict = (
                f"delta={tight_report.required_delta:.10f} is unreachable by "
                "any bounded BKZ block size, so this extreme is off-scale "
                "hard (no finite bit figure applies)"
            )

    if relaxed_bound >= q:
        relaxed_verdict = (
            f"bound {relaxed_bound:.3e} >= q, so Eq.(2) cannot hold and no "
            "estimate is meaningful"
        )
    else:
        relaxed_report = analyze_msis(
            n_module=n_module, d=d, q=q, beta=relaxed_bound
        )
        relaxed_costs = [
            v for v in relaxed_report.costs_bits.values() if v is not None
        ]
        relaxed_verdict = (
            f"{min(relaxed_costs):.0f}-{max(relaxed_costs):.0f} bits"
            if relaxed_costs else "no cost models resolved"
        )

    log2_volume = sum(b.log2_box_volume for b in block_tuple)
    slack = log2_volume - n_int * log2_q
    equivalent = (2.0 ** (log2_volume / total_columns) - 1.0) / 2.0

    return MixedBoundReport(
        blocks=block_tuple,
        n_int=n_int,
        log2_q=log2_q,
        tight_bound=tight,
        relaxed_bound=relaxed_bound,
        tight_verdict=tight_verdict,
        relaxed_verdict=relaxed_verdict,
        equivalent_uniform_bound=equivalent,
        slack_bits=slack,
    )


def paper_mixed_bounds(relaxed_bound: float | None = None) -> MixedBoundReport:
    """Gao Section 8 HMC: 64 message columns (bits), 60 randomness (2B=2)."""
    if relaxed_bound is None:
        from decimal import Decimal

        from .paper_bounds import gamma_bin_reduced

        relaxed_bound = float(
            2 * gamma_bin_reduced(8, 64, 56, 64, 2, Decimal(15), Decimal(15), 1, 60)
        )
    blocks = (
        ColumnBlock(
            name="message (dm)",
            columns=64 * 64,
            bound=1.0,
            rationale=(
                "bit commitments: each m_i in {0,1}, so dm = m1-m0 has "
                "entries in {-1,0,1}"
            ),
        ),
        ColumnBlock(
            name="randomness (dr)",
            columns=60 * 64,
            bound=2.0,
            rationale="r sampled from {-B..B} with B=1, so |dr| <= 2B = 2",
        ),
    )
    return analyze_mixed_bounds(
        blocks=blocks, n_module=29, d=64,
        q=2 ** 49 - 2 ** 18 + 2 ** 9 + 1,
        relaxed_bound=relaxed_bound,
    )


__all__ = [
    "ColumnBlock",
    "MixedBoundReport",
    "analyze_mixed_bounds",
    "paper_mixed_bounds",
]
