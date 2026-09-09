"""Gao Protocol 5 end-to-end: linear-equation satisfiability proof.

Ring-valued cycle masking, two rejection stages, abort/retry, verifier
that never sees c or rc. Research scaffold: finite-support reference
distributions, not exact D_3; toy parameters; no soundness proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Sequence

from .balance_composition import BalanceCompositionError, SignedAmount, build_balance_columns
from .hmc import HMCError, HMCKey, centered_coefficients, infinity_norm
from .linear_equation_transcript import (
    f0_in_canonical_range,
    reconstruct_f0_over_integers,
)
from .paper_bounds import gamma_le
from .protocol1_sampling import (
    FiniteDiscreteGaussian,
    Protocol1DistributionParameters,
    RejectionPolicy,
    SamplingError,
    XofByteSource,
    accept_rejection,
    coefficient_vector,
    sample_box_ring_vector,
    sample_gaussian_ring_vector,
    tail_for_sigma,
)
from .relations import decompose_unsigned
from .ring_challenge import (
    RingChallengeError,
    RingChallengeParameters,
    challenge_ring_element,
    derive_ring_challenge,
)
from .ring_commitment import EncodingError, RingElement


class Protocol5Error(ValueError):
    """Malformed Protocol 5 input or exhausted retry budget."""


def _tail_for_sigma(sigma: Decimal, minimum: int = 8) -> int:
    """Per-profile support tail; delegates to the shared helper (one source)."""
    return tail_for_sigma(sigma, multiplier=6, minimum=minimum)


def _constant_poly(value: int, params) -> RingElement:
    return RingElement.from_coeffs((value,) + (0,) * (params.n - 1), params)


def _zero_poly(params) -> RingElement:
    return RingElement.zero(params)


@dataclass(frozen=True)
class Protocol5Proof:
    """Public Protocol 5 transcript: D, response tail f_1..f_{k-1}, z."""

    commitment_d: tuple[RingElement, ...]
    response_tail: tuple[RingElement, ...]
    response_z: tuple[RingElement, ...]


@dataclass(frozen=True)
class Protocol5Result:
    proof: Protocol5Proof
    challenge_x: RingElement
    columns: tuple[int, ...]
    attempts: int
    weighted_sum: int
    conserved: bool
    bit_commitments: tuple[tuple[RingElement, ...], ...]
    lambdas: tuple[int, ...]


def compute_t3(signs: Sequence[int], p: int, w: int, k: int) -> Decimal:
    """Gao Protocol 2 step 2: T3 = max(-sum_{neg} lam, sum_{pos} lam)*p*sqrt(wk)."""
    positive = sum(value for value in signs if value > 0)
    negative = -sum(value for value in signs if value < 0)
    if min(p, w, k) <= 0:
        raise Protocol5Error("p, w, k must be positive")
    return Decimal(max(positive, negative) * p) * Decimal(w * k).sqrt()


def derive_ring_cycle_mask(
    sampled_tail: Sequence[RingElement],
    params,
) -> tuple[RingElement, ...]:
    """Ring-valued cycle mask: d_j = d~_j - 2*d~_{j+1}, d~_0 = d~_k = 0.

    sampled_tail supplies d~_1..d~_{k-1} as full ring elements. The
    telescoping identity sum_j 2^j d_j = d~_0 - 2^k d~_k = 0 holds
    COEFFICIENTWISE over Z (each coefficient is an independent integer
    cycle mask), which is what makes f_0 verifier-recoverable and the
    overflow gate sound. Gao eq.16 generalized from scalars to R.
    """
    k_minus_1 = len(sampled_tail)
    if k_minus_1 < 1:
        raise Protocol5Error("cycle mask needs at least one sampled coordinate")
    if any(value.params != params for value in sampled_tail):
        raise Protocol5Error("sampled mask parameter mismatch")
    d_tilde = (_zero_poly(params), *tuple(sampled_tail), _zero_poly(params))
    mask = tuple(
        d_tilde[j].sub(d_tilde[j + 1].scalar_mul(2))
        for j in range(len(d_tilde) - 1)
    )
    return mask


def ring_cycle_mask_weighted_sum_is_zero(
    mask: Sequence[RingElement],
) -> bool:
    """Verify sum_j 2^j d_j == 0 coefficientwise over the integers."""
    if not mask:
        return False
    params = mask[0].params
    if any(value.params != params for value in mask):
        return False
    n = params.n
    total = [0] * n
    for j, element in enumerate(mask):
        for index, coefficient in enumerate(centered_coefficients(element)):
            total[index] += (1 << j) * coefficient
    return all(value == 0 for value in total)


@dataclass(frozen=True)
class Protocol5Parameters:
    """Protocol 5 knobs: T3/T2' derived from paper formulas; verifier
    norm bounds are EXPLICIT RESEARCH bounds (paper's 6*phi3*T3*sqrt(d)
    style, not independently re-derived -- flagged, not certified)."""

    p: int
    w: int
    k: int
    B: int
    m: int
    d: int
    phi2: Decimal
    phi3: Decimal
    omega_l1: int
    account_count: int
    f_bound: Decimal
    z_bound: Decimal
    challenge_domain: bytes = b"PQCT-PROTOCOL5-CHALLENGE-V1"

    def __post_init__(self) -> None:
        if min(self.p, self.w, self.k, self.B, self.m, self.d) <= 0:
            raise Protocol5Error("Protocol 5 dimensions must be positive")
        if self.phi2 <= 0 or self.phi3 <= 0:
            raise Protocol5Error("phi2 and phi3 must be positive")
        if self.omega_l1 <= 0 or self.account_count <= 0:
            raise Protocol5Error("omega_l1 and account_count must be positive")
        if self.f_bound <= 0 or self.z_bound <= 0:
            raise Protocol5Error("verifier bounds must be positive")

    @property
    def t2_prime(self) -> Decimal:
        """T2' = B*w*p*sqrt(m*d*(||omega||_1^2 + S + 1)) -- Gao eq.(48).

        omega is the PUBLIC linear-function coefficient vector (lambda_i),
        S = account_count. Earlier code wrongly used Protocol 1's
        sqrt(3*m*d) binary T2 here; corrected against the paper's
        Theorem 2 / Appendix C eq.(48) via high-res PDF transcription.
        """
        inner = Decimal(self.m * self.d) * Decimal(
            self.omega_l1 * self.omega_l1 + self.account_count + 1
        )
        return Decimal(self.B * self.w * self.p) * inner.sqrt()

    @property
    def gamma_le_required(self) -> Decimal:
        """Gao Theorem 2: the HMC must be gamma_LE-binding for this relation.

        gamma_LE = 4*phi_3*m*d*B*w*p*sqrt(||omega||_1^2 + S + 1), computed
        from pqct.paper_bounds (paper-transcribed formula, not a placeholder).
        This is the bound the underlying commitment scheme must actually
        satisfy for Protocol 5's soundness theorem to apply.
        """
        return gamma_le(
            self.phi3, self.m, self.d, self.B, self.w, self.p,
            self.omega_l1, self.account_count,
        )

    @classmethod
    def from_research_bounds(
        cls, *, p: int, w: int, k: int, B: int, m: int, d: int,
        phi2: Decimal, phi3: Decimal, sign_max: int,
        omega_l1: int, account_count: int,
    ) -> "Protocol5Parameters":
        t3 = Decimal(sign_max * p) * Decimal(w * k).sqrt()
        inner = Decimal(m * d) * Decimal(omega_l1 * omega_l1 + account_count + 1)
        t2p = Decimal(B * w * p) * inner.sqrt()
        return cls(
            p=p, w=w, k=k, B=B, m=m, d=d, phi2=phi2, phi3=phi3,
            omega_l1=omega_l1, account_count=account_count,
            f_bound=Decimal(6) * phi3 * t3 * Decimal(d).sqrt(),
            z_bound=Decimal(2) * phi2 * t2p * Decimal(m * d).sqrt(),
        )


def derive_protocol5_challenge(
    statement: bytes,
    ring_params,
    p5: Protocol5Parameters,
    bit_commitments: Sequence[Sequence[RingElement]],
    commitment_d: Sequence[RingElement],
) -> RingElement:
    """Fiat-Shamir challenge bound to statement, B_i's, and D."""
    try:
        sparse = derive_ring_challenge(
            statement + b"|P5|" + p5.challenge_domain,
            ring_params,
            RingChallengeParameters(p5.w, p5.p),
            (*[tuple(row) for row in bit_commitments], tuple(commitment_d)),
        )
        return challenge_ring_element(sparse)
    except (RingChallengeError, TypeError, ValueError) as error:
        raise Protocol5Error(f"challenge derivation failed: {error}") from error


def compute_sign_max(lambdas: Sequence[int]) -> int:
    """max(sum of positive lambdas, -sum of negative lambdas) for T3."""
    positive = sum(value for value in lambdas if value > 0)
    negative = -sum(value for value in lambdas if value < 0)
    return max(positive, negative)


def protocol5_params_for_lambdas(
    lambdas: Sequence[int], *,
    p: int, w: int, k: int, B: int, m: int, d: int,
    phi2: Decimal, phi3: Decimal,
) -> Protocol5Parameters:
    """Build Protocol5Parameters consistent with a concrete lambda vector.

    omega_l1 = sum |lambda_i| and account_count = S are PUBLIC relation
    data; the verifier recomputes the T2'/z bound from them, so they must
    match the lambdas the proof actually uses.
    """
    if not lambdas:
        raise Protocol5Error("lambda vector cannot be empty")
    if any(value == 0 for value in lambdas):
        raise Protocol5Error("lambda entries must be nonzero")
    return Protocol5Parameters.from_research_bounds(
        p=p, w=w, k=k, B=B, m=m, d=d, phi2=phi2, phi3=phi3,
        sign_max=compute_sign_max(lambdas),
        omega_l1=sum(abs(value) for value in lambdas),
        account_count=len(lambdas),
    )


def _l2(elements: Sequence[RingElement]) -> Decimal:
    total = sum(
        coefficient * coefficient
        for element in elements
        for coefficient in centered_coefficients(element)
    )
    return Decimal(total).sqrt()


@dataclass(frozen=True)
class Protocol5Verification:
    """Per-gate verifier results (never uses c or r_c)."""

    f0_in_range: bool
    f_norms_ok: bool
    z_norm_ok: bool
    commitment_equation_ok: bool

    @property
    def accepted(self) -> bool:
        return (
            self.f0_in_range
            and self.f_norms_ok
            and self.z_norm_ok
            and self.commitment_equation_ok
        )


def verify_linear_equation(
    *,
    statement: bytes,
    key_c: HMCKey,
    bit_commitments: Sequence[Sequence[RingElement]],
    lambdas: Sequence[int],
    proof: Protocol5Proof,
    p5: Protocol5Parameters,
    challenge_x: RingElement | None = None,
) -> Protocol5Verification:
    """Gao Protocol 2 verifier steps 16-17 (minus Vbin composition).

    C is computed locally from the public B_i and lambdas (eq.11); f_0
    is reconstructed over the integers from the response tail; the
    transcript is accepted only if f_0 lies in R_q's centered range,
    all norms pass, and x*C + D = Com((f_0,f_1..); z).
    """
    params = key_c.params
    public = tuple(tuple(row) for row in bit_commitments)
    if len(public) != len(lambdas) or not public:
        raise Protocol5Error("commitment/lambda count mismatch")
    # The parameter set's omega/account fields must match the PUBLIC lambdas;
    # otherwise the T2'/z bound would be computed from a different relation.
    if p5.omega_l1 != sum(abs(value) for value in lambdas):
        raise Protocol5Error("p5.omega_l1 does not match the lambda vector")
    if p5.account_count != len(lambdas):
        raise Protocol5Error("p5.account_count does not match lambda count")
    if key_c.message_width != p5.k:
        raise Protocol5Error("HMC message width must equal k")
    if len(proof.response_tail) != p5.k - 1:
        raise Protocol5Error("response tail must have k-1 elements")
    if len(proof.response_z) != key_c.randomness_width:
        raise Protocol5Error("z width mismatch")
    if len(proof.commitment_d) != key_c.ring_rows:
        raise Protocol5Error("D row count mismatch")
    if any(value.params != params for value in (*proof.response_tail, *proof.response_z, *proof.commitment_d)):
        raise Protocol5Error("proof parameter mismatch")

    zero_rows = tuple(RingElement.zero(params) for _ in range(key_c.ring_rows))
    c_commitment = tuple(zero_rows)
    for lam, row in zip(lambdas, public):
        if len(row) != key_c.ring_rows:
            raise Protocol5Error("B_i row count mismatch")
        if any(value.params != params for value in row):
            raise Protocol5Error("B_i parameter mismatch")
        c_commitment = tuple(
            total.add(value.scalar_mul(lam))
            for total, value in zip(c_commitment, row)
        )

    x = challenge_x
    if x is None:
        x = derive_protocol5_challenge(statement, params, p5, public, proof.commitment_d)
    if x.params != params:
        raise Protocol5Error("challenge parameter mismatch")

    f0_int = reconstruct_f0_over_integers(proof.response_tail)
    gate_range = f0_in_canonical_range(f0_int, params.q)

    f0_element = RingElement.from_coeffs(
        tuple(value % params.q for value in f0_int), params
    )
    f_norms_ok = all(
        _l2((element,)) <= p5.f_bound
        for element in (f0_element, *proof.response_tail)
    )
    z_norm_ok = _l2(proof.response_z) <= p5.z_bound

    commitment_equation_ok = False
    if gate_range:
        try:
            lhs = tuple(
                x.mul(c_row).add(d_row)
                for c_row, d_row in zip(c_commitment, proof.commitment_d)
            )
            rhs = key_c.commit((f0_element, *proof.response_tail), proof.response_z)
            commitment_equation_ok = lhs == rhs
        except (HMCError, EncodingError, TypeError, ValueError):
            commitment_equation_ok = False

    return Protocol5Verification(
        f0_in_range=gate_range,
        f_norms_ok=f_norms_ok,
        z_norm_ok=z_norm_ok,
        commitment_equation_ok=commitment_equation_ok,
    )


def prove_linear_equation(
    *,
    seed: bytes,
    statement: bytes,
    key: HMCKey,
    amounts: Sequence[SignedAmount],
    bit_width: int,
    p5: Protocol5Parameters,
    phi2: Decimal,
    phi3: Decimal,
    max_attempts: int = 256,
    openings_override: Sequence[Sequence[RingElement]] | None = None,
) -> Protocol5Result:
    """Gao Protocol 2 prover for signed-amount conservation.

    Steps: decompose amounts to bits, commit B_i with r_{b,i} from
    S_B^m, derive c_j columns and r_c = sum lam_i r_{b,i}, sample the
    ring cycle mask d (D_{3,T3}, per-profile tail), D = Com(d; r_d),
    FS challenge x, f_1 = x*c_1 + d_1 (tail only), Rej stage 1
    (phi_3,T_3), z = x*r_c + r_d, Rej stage 2 (phi_2,T2'), abort and
    retry with a fresh attempt seed on rejection.

    Protocol 1 binary proofs for the B_i are NOT run here; composition
    with balance_transcript's per-amount proofs is the caller's job
    (steps 1/9 of the paper delegate to Pbin).
    """
    if not seed or not statement:
        raise Protocol5Error("seed and statement cannot be empty")
    if max_attempts <= 0:
        raise Protocol5Error("max_attempts must be positive")
    if bit_width != p5.k:
        raise Protocol5Error("bit width must equal k")
    if bit_width != key.message_width:
        raise Protocol5Error("HMC message width must equal k")
    params = key.params
    if key.randomness_width != p5.m:
        raise Protocol5Error("randomness width must equal m")

    signed = tuple(amounts)
    try:
        columns = build_balance_columns(signed, bit_width)
    except BalanceCompositionError as error:
        raise Protocol5Error(str(error)) from error
    lambdas = tuple(amount.sign for amount in signed)
    if p5.omega_l1 != sum(abs(value) for value in lambdas):
        raise Protocol5Error("p5.omega_l1 does not match the amount signs")
    if p5.account_count != len(lambdas):
        raise Protocol5Error("p5.account_count does not match the amount count")
    t3 = compute_t3(lambdas, p5.p, p5.w, p5.k)
    t2_prime = p5.t2_prime

    f_profile = FiniteDiscreteGaussian(phi3 * t3, _tail_for_sigma(phi3 * t3))
    z_profile = FiniteDiscreteGaussian(phi2 * t2_prime, _tail_for_sigma(phi2 * t2_prime))

    fixed_openings = None
    if openings_override is not None:
        # Validated OUTSIDE the retry loop so malformed input raises
        # instead of being swallowed into "no accepted transcript".
        fixed_openings = tuple(tuple(row) for row in openings_override)
        if len(fixed_openings) != len(signed):
            raise Protocol5Error("openings_override count differs from amounts")
        for row in fixed_openings:
            if len(row) != p5.m:
                raise Protocol5Error("override opening width differs from m")
            if any(value.params != params for value in row):
                raise Protocol5Error("override opening parameter mismatch")

    for attempt in range(1, max_attempts + 1):
        attempt_seed = seed + b"|attempt|" + attempt.to_bytes(8, "big")
        try:
            bits_rows = []
            openings = []
            commitments = []
            for index, amount in enumerate(signed):
                bits_int = decompose_unsigned(amount.value, bit_width)
                bits = tuple(
                    _constant_poly(bit, params) for bit in bits_int
                )
                if fixed_openings is not None:
                    opening = fixed_openings[index]
                else:
                    opening = sample_box_ring_vector(
                        XofByteSource(attempt_seed + b"|rb|" + index.to_bytes(4, "big")),
                        params, p5.m, p5.B,
                    )
                bits_rows.append(bits)
                openings.append(opening)
                commitments.append(key.commit(bits, opening))

            zero_rand = tuple(_zero_poly(params) for _ in range(p5.m))
            r_c = tuple(zero_rand)
            for lam, opening in zip(lambdas, openings):
                r_c = tuple(
                    total.add(value.scalar_mul(lam))
                    for total, value in zip(r_c, opening)
                )

            d_tilde_tail = sample_gaussian_ring_vector(
                XofByteSource(attempt_seed + b"|dtilde"),
                params, p5.k - 1, f_profile,
            )
            d = derive_ring_cycle_mask(d_tilde_tail, params)
            r_d = sample_gaussian_ring_vector(
                XofByteSource(attempt_seed + b"|rd"), params, p5.m, z_profile,
            )
            commitment_d = key.commit(d, r_d)

            x = derive_protocol5_challenge(
                statement, params, p5, commitments, commitment_d,
            )

            c_elements = tuple(_constant_poly(value, params) for value in columns.columns)
            f_tail = tuple(
                x.mul(c_element).add(d_element)
                for c_element, d_element in zip(c_elements[1:], d[1:])
            )

            policy3 = RejectionPolicy(phi3, t3)
            shift_f = tuple(
                x.mul(c_element)
                for c_element in c_elements[1:]
            )
            stage1 = accept_rejection(
                XofByteSource(attempt_seed + b"|rej3"),
                coefficient_vector(f_tail), coefficient_vector(shift_f), policy3,
            )
            if not stage1[0]:
                continue

            z = tuple(
                x.mul(rc).add(rd) for rc, rd in zip(r_c, r_d)
            )
            policy2 = RejectionPolicy(phi2, t2_prime)
            shift_z = tuple(x.mul(rc) for rc in r_c)
            stage2 = accept_rejection(
                XofByteSource(attempt_seed + b"|rej2"),
                coefficient_vector(z), coefficient_vector(shift_z), policy2,
            )
            if not stage2[0]:
                continue

            proof = Protocol5Proof(commitment_d, f_tail, z)
            verification = verify_linear_equation(
                statement=statement, key_c=key,
                bit_commitments=commitments, lambdas=lambdas,
                proof=proof, p5=p5, challenge_x=x,
            )
            if not verification.accepted:
                continue
            return Protocol5Result(
                proof=proof, challenge_x=x, columns=columns.columns,
                attempts=attempt, weighted_sum=columns.weighted_sum,
                conserved=columns.conserved,
                bit_commitments=tuple(commitments), lambdas=lambdas,
            )
        except (SamplingError, HMCError, EncodingError, Protocol5Error, TypeError, ValueError):
            continue

    raise Protocol5Error(
        f"no accepted Protocol 5 transcript in {max_attempts} attempts"
    )


__all__ = [
    "Protocol5Error",
    "Protocol5Parameters",
    "Protocol5Proof",
    "Protocol5Result",
    "Protocol5Verification",
    "compute_sign_max",
    "compute_t3",
    "derive_protocol5_challenge",
    "derive_ring_cycle_mask",
    "prove_linear_equation",
    "protocol5_params_for_lambdas",
    "ring_cycle_mask_weighted_sum_is_zero",
    "verify_linear_equation",
]







