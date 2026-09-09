"""Probe the working norm=2 path of lattice-estimator on Gao's paper profile.

Findings so far (this file's output is the evidence):
  - norm=oo path is BROKEN in the conda-forge Sage build:
    TypeError "Cannot convert mpz to sage.rings.integer.Integer"
  - norm=2 path WORKS and returns a real cost dict.

So the question becomes: what is the correct L2 length_bound to express
Gao's gamma_bin, which is an L-INFINITY coefficient bound?

Conservative mapping: ||z||_2 <= ||z||_inf * sqrt(len(z)), i.e.
length_bound = gamma_bin * sqrt(cols). That is valid and conservative
(it only ever UNDERSTATES security), but it inflates by sqrt(cols) and can
push the bound past q, which the estimator then reads as a trivial instance.
"""

import json
import math
import sys

from mpmath.libmp import backend
backend.gmpy = None  # keep mpmath off gmpy2 (does not fix norm=oo, but harmless)

from estimator import SIS
from estimator.reduction import ADPS16, BDGL16, MATZOV
from sage.all import ZZ, oo

sys.path.insert(0, "/mnt/c/Users/officeone/pq-ct-research")
from decimal import Decimal
from pqct.paper_bounds import gamma_bin_reduced

Q = 2 ** 49 - 2 ** 18 + 2 ** 9 + 1
N_MODULE = 29
D = 64
S = 2

# Paper's Section-8 profile: (d,w,p)=(64,56,8), k=64, m=60, phi1=phi2=15, B=1.
gb = gamma_bin_reduced(
    8, D, 56, 64, S, Decimal(15), Decimal(15), 1, 60
)
gb_f = float(gb)
print("gamma_bin (reduced, Eq.21) =", f"{gb:.6e}")
print("q                          =", f"{float(Q):.6e}")
print("gamma_bin < q              =", gb < Q)
print()

MODELS = (("ADPS16", ADPS16()), ("BDGL16", BDGL16()), ("MATZOV", MATZOV()))


def extract(cost):
    """Pull rop/bkz out of the nested cost structure: {'lattice': {...}}."""
    out = {}
    lat = cost.get("lattice") if isinstance(cost, dict) else None
    node = lat if isinstance(lat, dict) else cost
    for key in ("rop", "bkz", "d", "repeat", "hamming-dim"):
        try:
            if key in node:
                out[key] = float(node[key])
        except (TypeError, KeyError, ValueError):
            pass
    if not out and isinstance(node, dict):
        out["_raw_keys"] = sorted(node.keys())[:10]
    return out


for cols in (3904, N_MODULE * D):
    l2 = gb_f * math.sqrt(cols)
    print(f"--- cols={cols}  L2 bound = gamma_bin*sqrt(cols) = {l2:.6e}")
    print(f"    L2 bound < q ? {l2 < float(Q)}")
    for name, model in MODELS:
        try:
            p = SIS.Parameters(
                n=ZZ(N_MODULE), q=ZZ(Q), length_bound=l2, m=ZZ(cols), norm=2, tag=f"p{cols}"
            )
            cost = SIS.estimate(
                p, red_cost_model=model, deny_list=(), jobs=1,
                catch_exceptions=False, quiet=True,
            )
            got = extract(cost)
            rop = got.get("rop")
            bits = math.log2(rop) if rop and rop > 0 else None
            print(f"    {name:7s} -> OK {got} log2(rop)={bits}")
        except Exception as exc:
            print(f"    {name:7s} -> FAIL {type(exc).__name__}: {str(exc)[:110]}")
    print()

print("PROBE_DONE")
