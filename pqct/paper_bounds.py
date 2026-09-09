"""Gao et al. 2021/1674 exact bound formulas and parameter preconditions.

Transcribed from the published PDF at 500 dpi (two independent
transcriptions agreed), replacing earlier ad-hoc "research placeholder"
bounds with the paper's own formulas:

Theorem 1 (Protocol 1, S <= 2), with kappa = S(S-1)/2:
    precondition:  q/2 > 16*(w*phi_1)^2 * p * k * d
    gamma_bin   =  4*p^2 * sqrt(d^3 * w^3 *
                     (32*d*p^2*k^3*phi_1^4 + 3*phi_2^2*B^2*m^2))
    relations:     R_bin(B*sqrt(m*d))
                   R'_bin(8*m*d*w^2*p^2*phi_2*B*sqrt(3*m*d))
    completeness error: 1 - 1/(mu(phi_1)*mu(phi_2)), mu per Lemma 6

Theorem 2 (Protocol 5):
    gamma_LE = 4*phi_3*m*d*B*w*p * sqrt(||omega||_1^2 + S + 1)
    relations: R_LE(B*sqrt(m*d)), R'_LE(gamma_LE)
    completeness error: 1 - 1/(mu(phi_1)*mu(phi_2)*mu(phi_3))

These are the paper's STATED bounds. Computing them is bookkeeping; it
is not a proof that the implementation satisfies them, and it is not a
Module-SIS/Module-LWE hardness estimate.
"""

from __future__ import annotations

from decimal import Decimal
from math import log2, sqrt


class PaperBoundsError(ValueError):
    """Invalid input to a paper bound/precondition formula."""


def mu_phi(phi: Decimal) -> Decimal:
    """Lemma 6 / Algorithm 1: mu(phi) = exp(1/(2*phi) + 1/(2*phi^2)).

    Matches RejectionPolicy.mu in protocol1_sampling.py (same convention).
    """
    phi = Decimal(phi)
    if phi <= 0:
        raise PaperBoundsError("phi must be positive")
    return (Decimal(1) / (Decimal(2) * phi) + Decimal(1) / (Decimal(2) * phi * phi)).exp()


def kappa_for_s(s: int) -> int:
    """kappa = S(S-1)/2 (number of second-layer challenge pairs)."""
    if s < 1:
        raise PaperBoundsError("S must be >= 1")
    return s * (s - 1) // 2


# --- Theorem 1 (Protocol 1) ---

def protocol1_q_precondition_holds(
    q: int, w: int, phi1: Decimal, p: int, k: int, d: int,
) -> bool:
    """Check q/2 > 16*(w*phi_1)^2 * p * k * d (Theorem 1 precondition)."""
    if min(q, w, p, k, d) <= 0:
        raise PaperBoundsError("q,w,p,k,d must be positive")
    phi1 = Decimal(phi1)
    if phi1 <= 0:
        raise PaperBoundsError("phi1 must be positive")
    lhs = Decimal(q) / Decimal(2)
    rhs = Decimal(16) * (Decimal(w) * phi1) ** 2 * Decimal(p * k * d)
    return lhs > rhs


def gamma_bin(
    p: int, d: int, w: int, k: int,
    phi1: Decimal, phi2: Decimal, B: int, m: int,
) -> Decimal:
    """gamma_bin = 4*p^2*sqrt(d^3*w^3*(32*d*p^2*k^3*phi1^4 + 3*phi2^2*B^2*m^2))."""
    if min(p, d, w, k, B, m) <= 0:
        raise PaperBoundsError("p,d,w,k,B,m must be positive")
    phi1 = Decimal(phi1)
    phi2 = Decimal(phi2)
    if phi1 <= 0 or phi2 <= 0:
        raise PaperBoundsError("phi1 and phi2 must be positive")
    inner = (
        Decimal(32) * Decimal(d) * Decimal(p * p) * Decimal(k ** 3) * phi1 ** 4
        + Decimal(3) * phi2 ** 2 * Decimal(B * B) * Decimal(m * m)
    )
    front = Decimal(4) * Decimal(p * p) * (Decimal(d ** 3) * Decimal(w ** 3)).sqrt()
    return front * inner.sqrt()


def relation_rbin_bound(B: int, m: int, d: int) -> Decimal:
    """R_bin(B*sqrt(m*d))."""
    if min(B, m, d) <= 0:
        raise PaperBoundsError("B,m,d must be positive")
    return Decimal(B) * Decimal(m * d).sqrt()


def relation_rbin_prime_bound(m: int, d: int, w: int, p: int, phi2: Decimal, B: int) -> Decimal:
    """R'_bin(8*m*d*w^2*p^2*phi_2*B*sqrt(3*m*d))."""
    if min(m, d, w, p, B) <= 0:
        raise PaperBoundsError("m,d,w,p,B must be positive")
    phi2 = Decimal(phi2)
    if phi2 <= 0:
        raise PaperBoundsError("phi2 must be positive")
    return (
        Decimal(8) * Decimal(m * d) * Decimal(w * w) * Decimal(p * p) * phi2 * Decimal(B)
        * Decimal(3 * m * d).sqrt()
    )


def completeness_error_protocol1(phi1: Decimal, phi2: Decimal) -> Decimal:
    """1 - 1/(mu(phi_1)*mu(phi_2))."""
    return Decimal(1) - Decimal(1) / (mu_phi(Decimal(phi1)) * mu_phi(Decimal(phi2)))


def gamma_bin_reduced(
    p: int, d: int, w: int, k: int, S: int,
    phi1: Decimal, phi2: Decimal, B: int, m: int,
) -> Decimal:
    """Section 8 REDUCED binding bound: gamma_bin = max{B_Bin, B_Amor}.

    Gao's evaluation uses this instead of the unreduced Theorem 1 gamma_bin.
    The reduction (from [EZS+19]) additionally checks that
    ||(g_i*(x*1-g_i))_i|| is a factor 4d smaller than the theoretical bound,
    sacrificing completeness (error < 1%) for a much smaller binding bound.

        B_Bin  = 4p^2 * sqrt(d^3 w^3 (p^2 k^3 S^3 phi1^4
                                      + phi2^2 B^2 m^2 (S+1)))        (21)
        B_Amor = 2^(kappa+1) S B p^kappa w^(kappa-1) m d^2 phi2
                 * sqrt(m d (S+1)) * sum_{i=0}^{S-1} (wp)^i

    with kappa = S(S-1)/2. Transcribed from the 900-dpi PDF crop and
    VALIDATED by reproducing the paper's own printed number
    2*gamma_bin ~ 2.86e14 at S=2 (see tools/reproduce_paper_binding.py).
    """
    if min(p, d, w, k, S, B, m) <= 0:
        raise PaperBoundsError("p,d,w,k,S,B,m must be positive")
    phi1 = Decimal(phi1)
    phi2 = Decimal(phi2)
    if phi1 <= 0 or phi2 <= 0:
        raise PaperBoundsError("phi1 and phi2 must be positive")
    kap = kappa_for_s(S)
    b_bin = Decimal(4) * Decimal(p * p) * (
        Decimal(d ** 3) * Decimal(w ** 3) * (
            Decimal(p * p) * Decimal(k ** 3) * Decimal(S ** 3) * phi1 ** 4
            + phi2 ** 2 * Decimal(B * B) * Decimal(m * m) * Decimal(S + 1)
        )
    ).sqrt()
    wp_sum = sum((Decimal(w) * Decimal(p)) ** i for i in range(S))
    b_amor = (
        Decimal(2) ** (kap + 1)
        * Decimal(S) * Decimal(B) * Decimal(p) ** kap * Decimal(w) ** (kap - 1)
        * Decimal(m) * Decimal(d * d) * phi2
        * (Decimal(m * d) * Decimal(S + 1)).sqrt()
        * wp_sum
    )
    return max(b_bin, b_amor)


def eq2_rhs(n_module: int, d: int, q: int, delta: Decimal) -> Decimal:
    """Right-hand side of Gao Eq.(2): min{q, 2^(2*sqrt(n*d*log2(q)*log2(delta)))}.

    n is the MODULE rank and d the ring degree; n*d appears exactly once.
    Validated by reproducing the paper's printed 4.10e14 at its evaluation
    profile with delta = 1.0045.
    """
    if min(n_module, d, q) <= 0 or delta <= 1:
        raise PaperBoundsError("n,d,q must be positive and delta > 1")
    exponent = 2.0 * sqrt(n_module * d * log2(q) * log2(float(delta)))
    return min(Decimal(q), Decimal(2) ** Decimal(str(exponent)))


# --- Theorem 2 (Protocol 5) ---

def gamma_le(
    phi3: Decimal, m: int, d: int, B: int, w: int, p: int,
    omega_l1: int, s: int,
) -> Decimal:
    """gamma_LE = 4*phi_3*m*d*B*w*p*sqrt(||omega||_1^2 + S + 1)."""
    if min(m, d, B, w, p, omega_l1) <= 0 or s < 1:
        raise PaperBoundsError("m,d,B,w,p,omega_l1 must be positive and S >= 1")
    phi3 = Decimal(phi3)
    if phi3 <= 0:
        raise PaperBoundsError("phi3 must be positive")
    inner = Decimal(omega_l1 * omega_l1 + s + 1)
    return Decimal(4) * phi3 * Decimal(m * d) * Decimal(B) * Decimal(w) * Decimal(p) * inner.sqrt()


def completeness_error_protocol5(phi1: Decimal, phi2: Decimal, phi3: Decimal) -> Decimal:
    """1 - 1/(mu(phi_1)*mu(phi_2)*mu(phi_3))."""
    return Decimal(1) - Decimal(1) / (
        mu_phi(Decimal(phi1)) * mu_phi(Decimal(phi2)) * mu_phi(Decimal(phi3))
    )


__all__ = [
    "PaperBoundsError",
    "completeness_error_protocol1",
    "completeness_error_protocol5",
    "eq2_rhs",
    "gamma_bin",
    "gamma_bin_reduced",
    "gamma_le",
    "kappa_for_s",
    "mu_phi",
    "protocol1_q_precondition_holds",
    "relation_rbin_bound",
    "relation_rbin_prime_bound",
]

