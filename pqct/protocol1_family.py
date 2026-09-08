"""Interactive transcript families and audit checks for Protocol 1.

This module exercises the two-level extraction tree without pretending that a
Fiat--Shamir transcript can be rewound. It builds three accepting second-
challenge transcripts with fixed (zeta, E, F, G), then optionally builds two
such branches with distinct zeta values for the S=2 first-layer extractor.

Every generated response is audited in two domains:

* the verifier's explicit Euclidean norm bounds; and
* unreduced integer negacyclic arithmetic, so a modular equality cannot hide
  coefficient wraparound.

The implementation is a bounded research harness. Its integer audit only
checks the explicitly recorded coefficient comparisons and final aggregate
canonical representatives; it is not a proof that every intermediate
negacyclic product avoided modular wraparound. It does not establish HMC
binding, a knowledge reduction, SHVZK, Fiat--Shamir security, or lattice
security.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Sequence

from .binary_protocol1_ring import (
    RingProtocol1Error,
    RingProtocol1Parameters,
    RingProtocol1Proof,
    build_protocol1_ring_transcript,
    verify_protocol1_ring,
)
from .hmc import HMCKey, centered_coefficients
from .protocol1_extraction import (
    FirstLayerExtraction,
    SecondLayerExtraction,
    extract_first_layer_s2,
    extract_second_layer,
    extract_second_layer_pair,
    validate_first_layer_relation,
    validate_pairwise_consistency,
    validate_pairwise_negation,
    validate_third_x_transcript,
)
from .ring_commitment import RingElement


class FamilyError(ValueError):
    """Malformed family, failed audit, or inconsistent extraction."""


def _centered(element: RingElement) -> tuple[int, ...]:
    return centered_coefficients(element)


def _zero_vector(n: int) -> tuple[int, ...]:
    return (0,) * n


def _one_vector(n: int) -> tuple[int, ...]:
    return (1,) + (0,) * (n - 1)


def _add_int(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    if len(left) != len(right):
        raise FamilyError("integer ring vector dimensions differ")
    return tuple(a + b for a, b in zip(left, right))


def _sub_int(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    if len(left) != len(right):
        raise FamilyError("integer ring vector dimensions differ")
    return tuple(a - b for a, b in zip(left, right))


def _mul_int(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    """Unreduced multiplication in Z[X]/(X^n+1)."""
    if len(left) != len(right) or not left:
        raise FamilyError("integer ring operands must have equal nonzero width")
    n = len(left)
    result = [0] * n
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            index = i + j
            if index < n:
                result[index] += a * b
            else:
                result[index - n] -= a * b
    return tuple(result)


def _weighted_int(
    rows: Sequence[Sequence[RingElement]], zeta: RingElement,
) -> tuple[tuple[int, ...], ...]:
    """Compute zeta-power aggregation without reducing modulo q."""
    if not rows or not rows[0]:
        raise FamilyError("cannot aggregate an empty response matrix")
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise FamilyError("response row widths differ")
    n = zeta.params.n
    total = [_zero_vector(n) for _ in range(width)]
    power = _one_vector(n)
    zeta_int = _centered(zeta)
    for row in rows:
        for column, element in enumerate(row):
            total[column] = _add_int(total[column], _mul_int(power, _centered(element)))
        power = _mul_int(power, zeta_int)
    return tuple(total)


def _weighted_ring(
    rows: Sequence[Sequence[RingElement]], zeta: RingElement,
) -> tuple[RingElement, ...]:
    if not rows or not rows[0]:
        raise FamilyError("cannot aggregate an empty response matrix")
    width = len(rows[0])
    total = [RingElement.zero(zeta.params) for _ in range(width)]
    power = RingElement.from_coeffs(_one_vector(zeta.params.n), zeta.params)
    for row in rows:
        if len(row) != width:
            raise FamilyError("response row widths differ")
        for column, element in enumerate(row):
            total[column] = total[column].add(power.mul(element))
        power = power.mul(zeta)
    return tuple(total)


def _weighted_public(
    commitments: Sequence[Sequence[RingElement]], zeta: RingElement,
) -> tuple[RingElement, ...]:
    if not commitments or not commitments[0]:
        raise FamilyError("cannot aggregate empty public commitments")
    rows = len(commitments[0])
    if any(len(row) != rows for row in commitments):
        raise FamilyError("public commitment row counts differ")
    total = [RingElement.zero(zeta.params) for _ in range(rows)]
    power = RingElement.from_coeffs(_one_vector(zeta.params.n), zeta.params)
    for row in commitments:
        for index, element in enumerate(row):
            total[index] = total[index].add(power.mul(element))
        power = power.mul(zeta)
    return tuple(total)


def _l2_norm(elements: Sequence[RingElement]) -> Decimal:
    total = sum(
        coefficient * coefficient
        for element in elements
        for coefficient in _centered(element)
    )
    return Decimal(total).sqrt()


@dataclass
class _WraparoundChecker:
    modulus: int
    max_abs: int = 0
    checked_values: int = 0
    violations: list[str] | None = None

    def __post_init__(self) -> None:
        if self.modulus <= 2:
            raise FamilyError("modulus must be greater than two")
        if self.violations is None:
            self.violations = []

    @property
    def safe(self) -> bool:
        return not self.violations

    @property
    def checked(self) -> int:
        return self.checked_values

    def observe(self, label: str, expected: Sequence[int]) -> None:
        assert self.violations is not None
        for index, value in enumerate(expected):
            self.checked_values += 1
            self.max_abs = max(self.max_abs, abs(value))
            if 2 * abs(value) >= self.modulus:
                self.violations.append(
                    f"{label}[{index}] integer coefficient {value} is not below q/2"
                )

    def compare(
        self, label: str, expected: Sequence[int], actual: RingElement,
    ) -> None:
        self.observe(label, expected)
        assert self.violations is not None
        actual_coefficients = _centered(actual)
        if tuple(expected) != actual_coefficients:
            self.violations.append(
                f"{label} differs after canonical reduction: "
                f"expected={tuple(expected)!r}, actual={actual_coefficients!r}"
            )

    def report(self) -> "WraparoundReport":
        violations = tuple(self.violations or ())
        return WraparoundReport(
            safe=not violations,
            modulus=self.modulus,
            max_abs=self.max_abs,
            checked_values=self.checked_values,
            violations=violations,
        )


@dataclass(frozen=True)
class WraparoundReport:
    """Audit result for unreduced integer coefficients versus R_q values."""

    safe: bool
    modulus: int
    max_abs: int
    checked_values: int
    violations: tuple[str, ...]


@dataclass(frozen=True)
class ResponseAudit:
    """Norm and integer-arithmetic audit for one accepted response."""

    wraparound: WraparoundReport
    norm_ok: bool
    max_g_norm: Decimal
    zg_norm: Decimal
    zb_norm: Decimal
    norm_violations: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.wraparound.safe and self.norm_ok


def audit_response(
    proof: RingProtocol1Proof,
    x: RingElement,
    zeta: RingElement,
    base_key: HMCKey,
    key_e: HMCKey,
    key_f: HMCKey,
    key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    bits: Sequence[Sequence[RingElement]],
    openings: Sequence[Sequence[RingElement]],
    masks_t: Sequence[Sequence[RingElement]],
    mask_opening_e: Sequence[RingElement],
    mask_opening_f: Sequence[RingElement],
    mask_openings_t: Sequence[Sequence[RingElement]],
    params: RingProtocol1Parameters,
) -> ResponseAudit:
    """Audit response norms and unreduced witness-response identities."""
    del key_e, key_f, key_g, bit_commitments
    if x.params != base_key.params or zeta.params != base_key.params:
        raise FamilyError("challenge parameter mismatch in response audit")
    rows = tuple(tuple(row) for row in masks_t)
    bit_rows = tuple(tuple(row) for row in bits)
    opening_rows = tuple(tuple(row) for row in openings)
    if len(rows) != len(bit_rows) or len(rows) != len(opening_rows):
        raise FamilyError("audit witness row dimensions differ")
    if not bit_rows or any(len(row) != len(bit_rows[0]) for row in bit_rows):
        raise FamilyError("audit bit widths differ")
    if any(len(row) != len(bit_rows[index]) for index, row in enumerate(rows)):
        raise FamilyError("audit mask widths differ")
    if len(mask_opening_e) != base_key.randomness_width:
        raise FamilyError("audit r_e width differs")
    if len(mask_opening_f) != base_key.randomness_width:
        raise FamilyError("audit r_f width differs")
    if len(mask_openings_t) != len(rows):
        raise FamilyError("audit r_t row count differs")
    if any(len(row) != base_key.randomness_width for row in mask_openings_t):
        raise FamilyError("audit r_t width differs")

    checker = _WraparoundChecker(base_key.params.q)
    x_int = _centered(x)
    zeta_int = _centered(zeta)
    for vector_index, (bit_row, mask_row, response_row) in enumerate(
        zip(bit_rows, rows, proof.responses_g)
    ):
        for bit_index, (bit, mask, response) in enumerate(
            zip(bit_row, mask_row, response_row)
        ):
            g_expected = _add_int(_mul_int(x_int, _centered(bit)), _centered(mask))
            checker.compare(f"g[{vector_index}][{bit_index}]", g_expected, response)
            h_expected = _mul_int(g_expected, _sub_int(x_int, g_expected))
            checker.compare(f"h[{vector_index}][{bit_index}]", h_expected, response.mul(x.sub(response)))

    zg_expected = tuple(
        _add_int(_mul_int(x_int, _centered(re_value)), _centered(rf_value))
        for re_value, rf_value in zip(mask_opening_e, mask_opening_f)
    )
    if len(zg_expected) != len(proof.response_zg):
        raise FamilyError("audit z_g response width differs")
    for index, (expected, actual) in enumerate(zip(zg_expected, proof.response_zg)):
        checker.compare(f"z_g[{index}]", expected, actual)

    zbi_expected: list[tuple[int, ...]] = []
    for vector_index, (opening_row, mask_row) in enumerate(zip(opening_rows, mask_openings_t)):
        if len(opening_row) != len(mask_row):
            raise FamilyError("audit opening/mask row widths differ")
        row_values = []
        for coordinate, (opening, mask) in enumerate(zip(opening_row, mask_row)):
            expected = _add_int(_mul_int(x_int, _centered(opening)), _centered(mask))
            checker.observe(f"z_b[{vector_index}][{coordinate}]", expected)
            row_values.append(expected)
        zbi_expected.append(tuple(row_values))

    if not zbi_expected:
        raise FamilyError("audit requires at least one z_b row")
    width = len(zbi_expected[0])
    aggregate_expected = [_zero_vector(base_key.params.n) for _ in range(width)]
    power = _one_vector(base_key.params.n)
    for row in zbi_expected:
        for coordinate, value in enumerate(row):
            aggregate_expected[coordinate] = _add_int(aggregate_expected[coordinate], _mul_int(power, value))
        power = _mul_int(power, zeta_int)
    if len(proof.response_zb) != width:
        raise FamilyError("audit z_b response width differs")
    for index, (expected, actual) in enumerate(zip(aggregate_expected, proof.response_zb)):
        checker.compare(f"z_b[{index}]", expected, actual)

    weighted_expected = _weighted_int(proof.responses_g, zeta)
    weighted_actual = _weighted_ring(proof.responses_g, zeta)
    for index, (expected, actual) in enumerate(zip(weighted_expected, weighted_actual)):
        checker.compare(f"weighted_g[{index}]", expected, actual)

    norm_violations: list[str] = []
    g_norms = tuple(_l2_norm((value,)) for row in proof.responses_g for value in row)
    max_g_norm = max(g_norms, default=Decimal(0))
    if any(value > Decimal(params.g_bound) for value in g_norms):
        norm_violations.append(f"g coordinate norm exceeds {params.g_bound}: max={max_g_norm}")
    zg_norm = _l2_norm(proof.response_zg)
    if zg_norm > Decimal(params.zg_bound):
        norm_violations.append(f"z_g norm exceeds {params.zg_bound}: actual={zg_norm}")
    zb_norm = _l2_norm(proof.response_zb)
    if zb_norm > Decimal(params.zb_bound):
        norm_violations.append(f"z_b norm exceeds {params.zb_bound}: actual={zb_norm}")
    return ResponseAudit(checker.report(), not norm_violations, max_g_norm, zg_norm, zb_norm, tuple(norm_violations))


@dataclass(frozen=True)
class SecondLayerFamily:
    """Three accepting x transcripts with fixed zeta and E/F/G."""

    statement: bytes
    zeta: RingElement
    challenges: tuple[RingElement, ...]
    proofs: tuple[RingProtocol1Proof, ...]
    audits: tuple[ResponseAudit, ...]

    def extract(self) -> SecondLayerExtraction:
        return extract_second_layer(
            self.challenges,
            self.proofs,
            self.zeta,
            transcript_zetas=(self.zeta,) * len(self.proofs),
        )


@dataclass(frozen=True)
class TwoLayerExtractionTree:
    """Two zeta branches, each containing three x transcripts."""

    branches: tuple[SecondLayerFamily, SecondLayerFamily]
    second_layer: tuple[SecondLayerExtraction, SecondLayerExtraction]
    first_layer: FirstLayerExtraction


def _same_stage_commitments(proofs: Sequence[RingProtocol1Proof]) -> None:
    if len(proofs) != 3:
        raise FamilyError("a second-layer family requires three proofs")
    first = proofs[0]
    if any((proof.commitment_e, proof.commitment_f, proof.commitment_g) != (first.commitment_e, first.commitment_f, first.commitment_g) for proof in proofs[1:]):
        raise FamilyError("x transcripts do not share E/F/G")


def build_second_layer_family(
    statement: bytes, base_key: HMCKey, key_e: HMCKey, key_f: HMCKey, key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]], bits: Sequence[Sequence[RingElement]],
    openings: Sequence[Sequence[RingElement]], masks_t: Sequence[Sequence[RingElement]],
    mask_opening_e: Sequence[RingElement], mask_opening_f: Sequence[RingElement],
    mask_openings_t: Sequence[Sequence[RingElement]], zeta: RingElement,
    x_challenges: Sequence[RingElement], params: RingProtocol1Parameters, *,
    reject_unsafe: bool = True,
) -> SecondLayerFamily:
    """Build and audit three accepting transcripts for one zeta branch."""
    challenges = tuple(x_challenges)
    if params.max_vectors != 2:
        raise FamilyError("two-layer family is restricted to the paper's S=2 path")
    if len(bit_commitments) != 2:
        raise FamilyError("Protocol 1 S=2 extraction requires exactly two public commitments")
    if len(bits) != 2 or len(openings) != 2 or len(masks_t) != 2 or len(mask_openings_t) != 2:
        raise FamilyError("Protocol 1 S=2 extraction requires exactly two witness/mask rows")
    if len(challenges) != 3 or len({challenge.encode() for challenge in challenges}) != 3:
        raise FamilyError("second-layer family requires three distinct x challenges")
    if any(challenge.params != base_key.params for challenge in challenges) or zeta.params != base_key.params:
        raise FamilyError("challenge parameter mismatch")
    proofs = tuple(build_protocol1_ring_transcript(
        statement, base_key, key_e, key_f, key_g, bit_commitments, bits, openings,
        masks_t, mask_opening_e, mask_opening_f, mask_openings_t, params,
        zeta=zeta, challenge_x=challenge,
    ) for challenge in challenges)
    _same_stage_commitments(proofs)
    audits = tuple(audit_response(
        proof, challenge, zeta, base_key, key_e, key_f, key_g, bit_commitments,
        bits, openings, masks_t, mask_opening_e, mask_opening_f, mask_openings_t, params,
    ) for proof, challenge in zip(proofs, challenges))
    for challenge, proof in zip(challenges, proofs):
        if not verify_protocol1_ring(
            statement, base_key, key_e, key_f, key_g, bit_commitments, proof, params,
            zeta=zeta, challenge_x=challenge,
        ):
            raise FamilyError("generated transcript failed explicit verifier")
    extraction = extract_second_layer(
        challenges, proofs, zeta,
        transcript_zetas=(zeta,) * len(proofs),
    )
    pair_extractions = tuple(
        extract_second_layer_pair(
            (challenges[i], challenges[j]),
            (proofs[i], proofs[j]),
            zeta,
            transcript_zetas=(zeta, zeta),
        )
        for i, j in ((0, 1), (0, 2), (1, 2))
    )
    if not all(
        validate_pairwise_consistency(
            pair, proofs[i], proofs[j], challenges[i], challenges[j], zeta,
        )
        for pair, (i, j) in zip(pair_extractions, ((0, 1), (0, 2), (1, 2)))
    ):
        raise FamilyError("pairwise second-layer extraction is inconsistent")
    if not validate_pairwise_negation(
        pair_extractions[0],
        extract_second_layer_pair(
            (challenges[1], challenges[0]), (proofs[1], proofs[0]), zeta,
            transcript_zetas=(zeta, zeta),
        ),
    ):
        raise FamilyError("reversed second-layer pair failed negation check")
    if not validate_third_x_transcript(extraction, challenges[2], proofs[2], zeta):
        raise FamilyError("third x transcript is inconsistent with extracted openings")
    if reject_unsafe and any(not audit.ok for audit in audits):
        raise FamilyError(f"response audit failed: {[(a.wraparound.violations, a.norm_violations) for a in audits if not a.ok]!r}")
    return SecondLayerFamily(statement, zeta, challenges, proofs, audits)


def _check_relaxed_opening(key: HMCKey, commitment: Sequence[RingElement], relaxation: RingElement, message: Sequence[RingElement], randomness: Sequence[RingElement]) -> bool:
    try:
        return key.commit(message, randomness) == tuple(relaxation.mul(value) for value in commitment)
    except (TypeError, ValueError, RingProtocol1Error):
        return False


def extract_checked_second_layer(family: SecondLayerFamily, base_key: HMCKey, key_e: HMCKey, key_f: HMCKey, key_g: HMCKey, bit_commitments: Sequence[Sequence[RingElement]]) -> SecondLayerExtraction:
    """Extract and check all four relaxed-opening commitment equations."""
    extraction = family.extract()
    checks = (
        (base_key, _weighted_public(bit_commitments, family.zeta), extraction.opening_sum_b, "sum-B"),
        (key_g, family.proofs[0].commitment_g, extraction.opening_g, "G"),
        (key_e, family.proofs[0].commitment_e, extraction.opening_e, "E"),
        (key_f, family.proofs[0].commitment_f, extraction.opening_f, "F"),
    )
    for key, commitment, opening, label in checks:
        if not _check_relaxed_opening(key, commitment, opening.relaxation, opening.message, opening.randomness):
            raise FamilyError(f"{label} relaxed opening does not verify")
    return extraction


def build_two_layer_extraction_tree(
    statement: bytes, base_key: HMCKey, key_e: HMCKey, key_f: HMCKey, key_g: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]], bits: Sequence[Sequence[RingElement]],
    openings: Sequence[Sequence[RingElement]], masks_t: Sequence[Sequence[RingElement]],
    mask_opening_e: Sequence[RingElement], mask_opening_f: Sequence[RingElement],
    mask_openings_t: Sequence[Sequence[RingElement]], zeta_challenges: Sequence[RingElement],
    x_challenges: Sequence[RingElement], params: RingProtocol1Parameters, *,
    reject_unsafe: bool = True,
) -> TwoLayerExtractionTree:
    """Build two zeta branches and extract the S=2 first layer."""
    zetas = tuple(zeta_challenges)
    if len(zetas) != 2 or len({value.encode() for value in zetas}) != 2:
        raise FamilyError("two-layer tree requires two distinct zeta challenges")
    if any(value.params != base_key.params for value in zetas):
        raise FamilyError("zeta challenge parameter mismatch")
    branches = tuple(build_second_layer_family(
        statement, base_key, key_e, key_f, key_g, bit_commitments, bits, openings,
        masks_t, mask_opening_e, mask_opening_f, mask_openings_t, zeta, x_challenges,
        params, reject_unsafe=reject_unsafe,
    ) for zeta in zetas)
    second_layer = tuple(extract_checked_second_layer(
        branch, base_key, key_e, key_f, key_g, bit_commitments
    ) for branch in branches)
    if second_layer[0].opening_sum_b.relaxation != second_layer[1].opening_sum_b.relaxation:
        raise FamilyError("first-layer branches have different relaxations")
    first = extract_first_layer_s2(
        zetas,
        tuple(item.opening_sum_b.message for item in second_layer),
        tuple(item.opening_sum_b.randomness for item in second_layer),
    )
    for zeta, item in zip(zetas, second_layer):
        if not validate_first_layer_relation(first, zeta, item.opening_sum_b.message, item.opening_sum_b.randomness):
            raise FamilyError("first-layer extracted relation failed")
    factor = first.relaxation.mul(second_layer[0].opening_sum_b.relaxation)
    for index, commitment in enumerate(bit_commitments[:2]):
        opening = first.opening_b0 if index == 0 else first.opening_b1
        if base_key.commit(opening.message, opening.randomness) != tuple(factor.mul(value) for value in commitment):
            raise FamilyError(f"first-layer B[{index}] relaxed opening failed")
    return TwoLayerExtractionTree((branches[0], branches[1]), (second_layer[0], second_layer[1]), first)


__all__ = [
    "FamilyError", "ResponseAudit", "SecondLayerFamily",
    "TwoLayerExtractionTree", "WraparoundReport", "audit_response",
    "build_second_layer_family", "build_two_layer_extraction_tree",
    "extract_checked_second_layer",
]
