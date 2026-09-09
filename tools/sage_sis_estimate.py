"""VERIFIED Module-SIS hardness via the real lattice-estimator (needs Sage).

This is blocker item 5: replace the self-built cited-constants approximation
in pqct/lattice_estimate.py with the actual Albrecht/Player/Scott
`lattice-estimator` (github.com/malb/lattice-estimator).

REQUIRES SAGE. It does not run under the project's plain CPython venv.
Run it from the sandboxed WSL user created for this repo:

    wsl -u pqct -e bash -lc '~/miniforge3/envs/sage/bin/sage -python \
        /mnt/c/Users/officeone/pq-ct-research/tools/sage_sis_estimate.py'

Sandbox properties (verified): internet egress allowed, ALL RFC1918/LAN
ranges blocked by an nftables uid-scoped table, no sudo.

The chain mirrors pqct.parameter_validation:
  Gao relation bound (gamma_bin / gamma_LE, Theorem 1/2)
    -> treated as the M-SIS solution norm bound (inf-norm -> L2 over m*d
       coefficients, conservative: assumes the bound saturates every
       coordinate)
    -> estimator.SIS.estimate under classical and quantum cost models.

Output is JSON. Nothing here is a security certification; it is the
verified-estimator input to that judgement, and the norm-bound mapping
from a ring relation to an integer SIS instance is an INTERPRETATION
that a lattice cryptographer must confirm.
"""

from __future__ import annotations

import json
import math
import sys
from decimal import Decimal

from estimator import SIS
from estimator.reduction import ADPS16, BDGL16, MATZOV

# gamma_bin comes from the pure-stdlib module (no Sage needed there).
sys.path.insert(0, "/mnt/c/Users/officeone/pq-ct-research")
from pqct.paper_bounds import gamma_bin

# Gao et al. 2021/1674 reported evaluation profile.
PAPER_Q = 2**49 - 2**18 + 2**9 + 1
PAPER_N_MODULE = 29   # SIS rank (NOT the ring degree)
PAPER_D = 64          # ring degree
PAPER_M = 60          # randomness width
PAPER_V = 1           # message columns for the binding argument
PAPER_W = 56          # challenge Hamming weight
PAPER_P = 8           # challenge coefficient bound
PAPER_K = 64          # amount bit width

COST_MODELS = (
    ("classical_ADPS16", ADPS16),
    ("classical_BDGL16", BDGL16),
    ("quantum_MATZOV", MATZOV),
)


def estimate_sis(*, rows: int, cols: int, q: int, l2_bound: float) -> dict:
    """Run estimator.SIS for each cost model; report best attack + rop.

    The verified estimator REJECTS a norm bound >= q as "SIS trivially easy"
    (a solution can then be read off directly). That rejection is reported
    here as an explicit ill-posed verdict instead of an exception, because
    it is a substantive finding about the parameter set, not a tool error.
    """
    out = {}
    if l2_bound >= q:
        return {
            "ill_posed": True,
            "reason": (
                "norm bound >= q: the verified estimator refuses this instance "
                "('SIS trivially easy. Please set norm bound < q.'). Any "
                "bit-security number produced from it is meaningless."
            ),
            "l2_bound": l2_bound,
            "q": q,
        }
    params = SIS.Parameters(n=rows, q=q, length_bound=l2_bound, m=cols, norm=2)
    for name, model in COST_MODELS:
        try:
            est = SIS.estimate(
                params, red_cost_model=model, jobs=1,
                catch_exceptions=True, quiet=True,
            )
            items = [(k, c) for k, c in est.items() if c is not None]
            if not items:
                out[name] = {"error": "no attacks returned"}
                continue
            label, best = min(items, key=lambda kv: float(kv[1].rop))
            rop = float(best.rop)
            out[name] = {
                "best_attack": label,
                "rop": rop,
                "log2_rop": math.log2(rop) if rop > 0 else None,
            }
        except Exception as error:  # noqa: BLE001 - report, never hide
            out[name] = {"error": f"{type(error).__name__}: {error}"}
    return out


def max_phi1_for_feasible_bound(*, q: int, p: int, d: int, w: int, k: int,
                                phi2: Decimal, B: int, m: int) -> Decimal:
    """Largest phi_1 keeping gamma_bin < q (Gao Eq.(2) needs min{q,...} > beta).

    gamma_bin = 4 p^2 sqrt(d^3 w^3 (32 d p^2 k^3 phi_1^4 + 3 phi_2^2 B^2 m^2))
    is monotone increasing in phi_1, so bisect for the crossover.
    """
    lo, hi = Decimal("0.01"), Decimal("10000")
    if gamma_bin(p, d, w, k, lo, phi2, B, m) >= q:
        return Decimal(0)
    if gamma_bin(p, d, w, k, hi, phi2, B, m) < q:
        return hi
    for _ in range(200):
        mid = (lo + hi) / 2
        if gamma_bin(p, d, w, k, mid, phi2, B, m) < q:
            lo = mid
        else:
            hi = mid
    return lo


def main() -> None:
    rows = PAPER_N_MODULE * PAPER_D
    cols = (PAPER_M + PAPER_V) * PAPER_D

    # Protocol 1 binary-proof dimensions (paper profile).
    p, w, k = PAPER_P, PAPER_W, PAPER_K
    phi2 = Decimal("11")
    B, m = 1, PAPER_M

    # phi_1 = 11 is the value used in our parameter_validation example.
    phi1 = Decimal(sys.argv[1]) if len(sys.argv) > 1 else Decimal("11")
    gb = gamma_bin(p, PAPER_D, w, k, phi1, phi2, B, m)

    # Conservative inf-norm -> L2 conversion: assume every one of the `cols`
    # integer coefficients saturates the inf-norm bound.
    l2_bound = math.sqrt(cols) * float(gb)

    feasible_phi1 = max_phi1_for_feasible_bound(
        q=PAPER_Q, p=p, d=PAPER_D, w=w, k=k, phi2=phi2, B=B, m=m,
    )

    result = {
        "tool": "malb/lattice-estimator (VERIFIED, not self-built)",
        "warning": (
            "ring-relation -> integer-SIS norm mapping is an INTERPRETATION; "
            "requires a lattice cryptographer's confirmation. Not a security "
            "certification and not a 128-bit claim."
        ),
        "input": {
            "q": PAPER_Q,
            "q_bits": PAPER_Q.bit_length(),
            "sis_rank_n_module": PAPER_N_MODULE,
            "ring_degree_d": PAPER_D,
            "integer_rows": rows,
            "integer_cols": cols,
            "phi1": str(phi1),
            "phi2": str(phi2),
            "gamma_bin_inf_bound": str(gb),
            "l2_bound_conservative": l2_bound,
        },
        "feasibility": {
            "gamma_bin_lt_q": float(gb) < PAPER_Q,
            "l2_bound_lt_q": l2_bound < PAPER_Q,
            "max_phi1_with_gamma_bin_lt_q": str(feasible_phi1),
            "note": (
                "Gao Eq.(2) requires min{q, 2^...} > beta; a bound >= q makes "
                "the SIS instance trivially easy, so the relation bound must "
                "stay below q for the hardness argument to be meaningful."
            ),
        },
        "estimates_at_requested_phi1": estimate_sis(
            rows=rows, cols=cols, q=PAPER_Q, l2_bound=l2_bound,
        ),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
