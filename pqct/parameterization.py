"""Parameter candidates and conservative checks for the PQ-CT experiment.

These are research candidates, not security parameters. The module refuses to
label them secure; it only derives dimensions, rough norm budgets, and emits a
machine-readable review record.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
from typing import Any


@dataclass(frozen=True)
class ParameterCandidate:
    name: str
    n: int
    q: int
    m: int
    d: int
    w: int
    precision_bits: int
    amount_bits: int
    max_inputs: int
    max_outputs: int
    sigma_mask: float
    sigma_opening: float
    challenge_bound: int
    response_bound: int
    opening_bound: int
    security_label: str = "UNASSESSED_RESEARCH_CANDIDATE"

    def __post_init__(self) -> None:
        if self.n <= 0 or self.q <= 2 or self.m <= 0 or self.d <= 0 or self.w <= 0:
            raise ValueError("ring and matrix dimensions must be positive")
        if self.q % (2 * self.n) != 1:
            raise ValueError("q must be 1 mod 2n for the negacyclic NTT candidate")
        if min(self.precision_bits, self.amount_bits, self.max_inputs, self.max_outputs) <= 0:
            raise ValueError("bit widths and transaction limits must be positive")
        if self.max_inputs > self.w or self.max_outputs > self.w:
            raise ValueError("transaction limits exceed declared weight budget")
        if self.sigma_mask <= 0 or self.sigma_opening <= 0:
            raise ValueError("sampling widths must be positive")
        if min(self.challenge_bound, self.response_bound, self.opening_bound) <= 0:
            raise ValueError("challenge and response bounds must be positive")
        if self.challenge_bound >= self.q // 4:
            raise ValueError("toy challenge must stay far below q until ring-valued FS is implemented")

    @property
    def modulus_bits(self) -> int:
        return self.q.bit_length()

    @property
    def message_columns(self) -> int:
        return self.amount_bits

    @property
    def ring_commitment_elements(self) -> int:
        return self.d * self.m

    @property
    def public_matrix_coefficients(self) -> int:
        return self.d * (self.m + self.w)

    @property
    def rough_response_budget(self) -> int:
        # Conservative pre-estimator budget for the toy harness only.
        return self.challenge_bound + 2 * self.sigma_mask * self.amount_bits

    def review_record(self) -> dict[str, Any]:
        data = asdict(self)
        data.update(
            modulus_bits=self.modulus_bits,
            message_columns=self.message_columns,
            ring_commitment_elements=self.ring_commitment_elements,
            public_matrix_coefficients=self.public_matrix_coefficients,
            rough_response_budget=self.rough_response_budget,
            warnings=[
                "Not a security estimate.",
                "No Module-SIS/LWE estimator has been run.",
                "No exact D1/D2/D3 sampler or ring-valued Fiat-Shamir challenge is implemented.",
                "Do not use for money, keys, or consensus.",
            ],
        )
        return data


def candidate_set() -> tuple[ParameterCandidate, ...]:
    """Return deliberately conservative experiment candidates."""
    return (
        ParameterCandidate(
            name="toy-ntt-32",
            n=32,
            q=12289,
            m=8,
            d=32,
            w=16,
            precision_bits=8,
            amount_bits=8,
            max_inputs=2,
            max_outputs=2,
            sigma_mask=3.2,
            sigma_opening=2.4,
            challenge_bound=15,
            response_bound=256,
            opening_bound=256,
        ),
        ParameterCandidate(
            name="toy-ntt-64",
            n=64,
            q=786433,
            m=16,
            d=64,
            w=32,
            precision_bits=16,
            amount_bits=16,
            max_inputs=4,
            max_outputs=4,
            sigma_mask=4.0,
            sigma_opening=3.0,
            challenge_bound=31,
            response_bound=1024,
            opening_bound=1024,
        ),
    )


def render_report(candidates: tuple[ParameterCandidate, ...] | None = None) -> str:
    selected = candidates or candidate_set()
    return json.dumps(
        {
            "status": "research-only",
            "candidates": [candidate.review_record() for candidate in selected],
        },
        indent=2,
        sort_keys=True,
    )
