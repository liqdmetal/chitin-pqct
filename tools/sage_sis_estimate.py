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
from sage.all import ZZ, oo

# gamma_bin comes from the pure-stdlib module (no Sage needed there).
sys.path.insert(0, "/mnt/c/Users/officeone/pq-ct-research")
from pqct.paper_bounds import gamma_bin_reduced

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
    # INSTANCES, not classes: SIS.estimate calls model.short_vectors(beta, d)
    # and passing the class shifts self/beta, producing a misleading
    # "short_vectors() missing 1 required positional argument: 'd'" error.
    ("classical_ADPS16", ADPS16()),
    ("classical_BDGL16", BDGL16()),
    ("quantum_MATZOV", MATZOV()),
)


def estimate_sis(*, rows: int, cols: int, q: int, inf_bound: float) -> dict:
    """Run estimator.SIS for each cost model; report best attack + rop.

    The bound is an INFINITY-norm (coefficientwise) bound and is passed
    straight through with norm=oo -- the estimator's documented convention
    (see its Dilithium3_MSIS_WkUnf example). An earlier version wrongly
    inflated it by sqrt(cols) into an L2 bound; that inflation was both
    unnecessary and the reason the instance looked ill-posed.

    The verified estimator REJECTS a norm bound >= q as "SIS trivially easy".
    That is reported as an explicit ill-posed verdict rather than raised,
    because it is a substantive statement about the parameter set.

    NOTE: in the current sandbox this function cannot complete -- the conda
    Sage build fails inside mpmath with "Cannot convert mpz to
    sage.rings.integer.Integer" for every cost model (a gmpy2/mpfr ABI issue,
    not an input error). The call construction below is the corrected one,
    verified against the tool's own signatures; it will produce numbers once
    run in a working Sage environment.
    """
    out = {}
    if inf_bound >= q:
        return {
            "ill_posed": True,
            "reason": (
                "norm bound >= q: the verified estimator refuses this instance "
                "('SIS trivially easy. Please set norm bound < q.'). Any "
                "bit-security number produced from it is meaningless."
            ),
            "inf_bound": inf_bound,
            "q": q,
        }
    params = SIS.Parameters(
        n=ZZ(rows), q=ZZ(q), length_bound=ZZ(int(inf_bound)),
        m=ZZ(cols), norm=oo,
    )
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
                                S: int, phi2: Decimal, B: int, m: int) -> Decimal:
    """Largest phi_1 keeping gamma_bin < q (Gao Eq.(2) needs min{q,...} > beta).

    Uses the REDUCED Section-8 bound gamma_bin_reduced (Eq.21), which is what
    the paper's own evaluation uses; the unreduced Theorem 1 bound is ~16x
    larger and crosses q far earlier. Monotone increasing in phi_1, so bisect.
    """
    lo, hi = Decimal("0.01"), Decimal("10000")
    if gamma_bin_reduced(p, d, w, k, S, lo, phi2, B, m) >= q:
        return Decimal(0)
    if gamma_bin_reduced(p, d, w, k, S, hi, phi2, B, m) < q:
        return hi
    for _ in range(200):
        mid = (lo + hi) / 2
        if gamma_bin_reduced(p, d, w, k, S, mid, phi2, B, m) < q:
            lo = mid
        else:
            hi = mid
    return lo


def main() -> None:
    rows = PAPER_N_MODULE * PAPER_D
    cols = (PAPER_M + PAPER_V) * PAPER_D
    S = 2

    # Protocol 1 binary-proof dimensions. phi_1 = phi_2 = 15 is the paper's
    # OWN evaluation setting (Section 7, "under settings: phi1 = phi2 = 15").
    p, w, k = PAPER_P, PAPER_W, PAPER_K
    phi2 = Decimal("15")
    B, m = 1, PAPER_M
    phi1 = Decimal(sys.argv[1]) if len(sys.argv) > 1 else Decimal("15")
    gb = gamma_bin_reduced(p, PAPER_D, w, k, S, phi1, phi2, B, m)

    # gamma_bin is an infinity-norm (coefficientwise) bound; pass it straight
    # through with norm=oo. No sqrt(cols) L2 inflation (that was wrong).
    inf_bound = float(gb)

    feasible_phi1 = max_phi1_for_feasible_bound(
        q=PAPER_Q, p=p, d=PAPER_D, w=w, k=k, S=S, phi2=phi2, B=B, m=m,
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
            "S": S,
            "gamma_bin_reduced_inf_bound": str(gb),
            "norm_used": "infinity (norm=oo), bound passed through unmodified",
        },
        "feasibility": {
            "gamma_bin_lt_q": inf_bound < PAPER_Q,
            "max_phi1_with_gamma_bin_lt_q": str(feasible_phi1),
            "paper_prints_2_gamma_bin": "~2.86e14",
            "ours_2_gamma_bin": f"{2 * inf_bound:.4e}",
            "note": (
                "Gao Eq.(2) requires min{q, 2^...} > beta; a bound >= q makes "
                "the SIS instance trivially easy, so the relation bound must "
                "stay below q for the hardness argument to be meaningful."
            ),
        },
        "estimates_at_requested_phi1": estimate_sis(
            rows=rows, cols=cols, q=PAPER_Q, inf_bound=inf_bound,
        ),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
