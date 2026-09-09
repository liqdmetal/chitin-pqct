"""Reproduce Gao Section 7/8 published binding numbers (Eq.21, B_Bin/B_Amor).

Paper's own evaluation params (line ~1600): phi_1 = phi_2 = 15, B = 1,
(d,w,p) = (64,56,8), q = 2^49-2^18+2^9+1, (n,m) = (29,60).
Paper's published result at S=2: gamma_bin ~ 2.86e14, which is smaller
than min{q, 2^(2nd log q log delta)} ~ 4.10e14 in Eq.(2).

If our transcription reproduces those two printed numbers, the formulas
are right -- and the earlier "gamma_bin >= q, instance trivially easy"
verdict is confirmed to have come from a WRONG phi_1 guess (11) applied
to the UNREDUCED Theorem 1 bound, not from a paper defect.
"""

from decimal import Decimal, getcontext

import os
import sys

# Repo root on sys.path so the delegated calls can import pqct.paper_bounds
# when this script is run directly from tools/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

getcontext().prec = 60

PHI1 = Decimal(15)
PHI2 = Decimal(15)
B = Decimal(1)
D = Decimal(64)
W = Decimal(56)
P = Decimal(8)
N_MOD = Decimal(29)
M = Decimal(60)
K = Decimal(64)          # amount bit width
S = 2
Q = 2**49 - 2**18 + 2**9 + 1
DELTA = Decimal("1.0045")   # paper's cited root Hermite factor


def kappa(s: int) -> int:
    return s * (s - 1) // 2


def gamma_bin_theorem1(s: int) -> Decimal:
    """UNREDUCED Theorem 1 bound (what we used before, with wrong phi)."""
    kap = Decimal(kappa(s))
    inner = (
        Decimal(32) * D * P**2 * K**3 * PHI1**4
        + Decimal(3) * PHI2**2 * B**2 * M**2
    )
    return Decimal(4) * P**2 * (D**3 * W**3 * inner).sqrt()


def b_bin(s: int) -> Decimal:
    """Eq.(21) reduced binary-constraint bound B_Bin."""
    inner = (
        P**2 * K**3 * Decimal(s) ** 3 * PHI1**4
        + PHI2**2 * B**2 * M**2 * Decimal(s + 1)
    )
    return Decimal(4) * P**2 * (D**3 * W**3 * inner).sqrt()


def b_amor(s: int) -> Decimal:
    """Partial-amortization bound B_Amor."""
    kap = kappa(s)
    total = sum((W * P) ** i for i in range(s))
    return (
        Decimal(2) ** (kap + 1)
        * Decimal(s) * B * P**kap * W ** (kap - 1)
        * M * D**2 * PHI2
        * (M * D * Decimal(s + 1)).sqrt()
        * Decimal(total)
    )


def gamma_bin_reduced(s: int) -> Decimal:
    """max(B_Bin, B_Amor) -- delegates to the single implementation in
    pqct.paper_bounds (validated against the paper's printed 2.86e14)."""
    from pqct.paper_bounds import gamma_bin_reduced as _impl
    return _impl(
        int(P), int(D), int(W), int(K), s,
        PHI1, PHI2, int(B), int(M),
    )


def eq2_rhs(s: int) -> Decimal:
    """min{q, 2^(2*sqrt(n*d*log2(q)*log2(delta)))} -- delegates to
    pqct.paper_bounds (n*d appears once; validated vs printed 4.10e14)."""
    from pqct.paper_bounds import eq2_rhs as _impl
    return _impl(int(N_MOD), int(D), Q, DELTA)


if __name__ == "__main__":
    print("paper's printed targets (S=2): 2*gamma_bin ~ 2.86e14, min{q,...} ~ 4.10e14")
    print()
    print("UNREDUCED Theorem 1 bound (phi=15):", f"{gamma_bin_theorem1(S):.4e}")
    print("B_Bin  (Eq.21):                 ", f"{b_bin(S):.4e}")
    print("B_Amor:                         ", f"{b_amor(S):.4e}")
    print("gamma_bin = max(B_Bin,B_Amor):  ", f"{gamma_bin_reduced(S):.4e}")
    print("2*gamma_bin (paper prints this):", f"{2*gamma_bin_reduced(S):.4e}", "  <- compare to 2.86e14")
    print("Eq.(2) RHS min{q,...}:          ", f"{eq2_rhs(S):.4e}", "  <- compare to 4.10e14")
    print()
    print("B_Amor < B_Bin (paper claims yes for S<=2):", b_amor(S) < b_bin(S))
    print("2*gamma_bin < Eq2 RHS (paper's claim):      ", 2*gamma_bin_reduced(S) < eq2_rhs(S))
    print("gamma_bin < q (instance well-posed):        ", gamma_bin_reduced(S) < Decimal(Q))
    print()
    # Reproduction check against the paper's two printed numbers.
    two_gb = float(2 * gamma_bin_reduced(S))
    rhs = float(eq2_rhs(S))
    print(f"reproduces 2.86e14 within 1%: {abs(two_gb - 2.86e14)/2.86e14 < 0.01}  (got {two_gb:.3e})")
    print(f"reproduces 4.10e14 within 2%: {abs(rhs - 4.10e14)/4.10e14 < 0.02}  (got {rhs:.3e})")
