"""Bracket the norm-mapping question: both ends of the interpretive range.

gamma_bin (Eq.21 reduced) = 1.4318e14 is an L-INFINITY coefficient bound.
q = 5.6295e14. The estimator's norm=2 path works; norm=oo is broken in this
conda build ("Cannot convert mpz to sage.rings.integer.Integer").

So gamma_bin must be expressed as an L2 bound. Two mappings bracket the range:

  CONSERVATIVE: ||z||_2 <= ||z||_inf * sqrt(cols)
                = 1.4318e14 * sqrt(3904) ~= 8.95e15  -> EXCEEDS q
                -> estimator refuses ("SIS trivially easy"). Valid but
                   useless: a bigger ball = easier problem = understated
                   security, and past q it returns nothing at all.

  OPTIMISTIC  : ||z||_2 = ||z||_inf (treat the coefficientwise bound as the
                L2 bound, i.e. assume only one nonzero coefficient)
                = 1.4318e14 < q -> well-posed, returns numbers.
                But it UNDERSTATES the true L2 norm, so it OVERSTATES
                security. Reporting it as the security level is unsafe.

Neither mapping is justified by the paper. This script measures BOTH so the
range is explicit, and prints a verdict rather than picking a flattering one.
"""

import math
import sys
from decimal import Decimal

from estimator import SIS
from estimator.reduction import ADPS16, BDGL16, MATZOV
from sage.all import ZZ

sys.path.insert(0, "/mnt/c/Users/officeone/pq-ct-research")
from pqct.paper_bounds import gamma_bin_reduced

Q = 2 ** 49 - 2 ** 18 + 2 ** 9 + 1
N_MODULE, D, S = 29, 64, 2
COLS = 3904

gb = gamma_bin_reduced(8, D, 56, 64, S, Decimal(15), Decimal(15), 1, 60)
gb_f = float(gb)
MODELS = (("ADPS16", ADPS16()), ("BDGL16", BDGL16()), ("MATZOV", MATZOV()))

print(f"gamma_bin(reduced) = {gb:.6e}   q = {float(Q):.6e}")
print(f"gamma_bin < q ? {gb < Q}    cols = {COLS}")
print(f"conservative L2 = gamma_bin*sqrt(cols) = {gb_f*math.sqrt(COLS):.6e}"
      f"   < q ? {gb_f*math.sqrt(COLS) < float(Q)}")
print()


def run(label, bound):
    print(f"=== {label}: length_bound = {bound:.6e}")
    if bound >= float(Q):
        print("    SKIP: bound >= q, estimator refuses (trivially easy).")
        print()
        return
    for name, model in MODELS:
        try:
            p = SIS.Parameters(n=ZZ(N_MODULE), q=ZZ(Q), length_bound=bound,
                               m=ZZ(COLS), norm=2, tag=label)
            cost = SIS.estimate(p, red_cost_model=model, jobs=1,
                                catch_exceptions=False, quiet=True)
            node = cost.get("lattice") if isinstance(cost, dict) else cost
            node = node if isinstance(node, dict) else cost
            rop = float(node["rop"]) if "rop" in node else None
            bkz = float(node["bkz"]) if "bkz" in node else None
            bits = math.log2(rop) if rop and rop > 0 else None
            print(f"    {name:7s} -> rop={rop}  log2(rop)={bits}  bkz={bkz}"
                  f"  keys={sorted(node.keys())[:8]}")
        except Exception as exc:
            print(f"    {name:7s} -> FAIL {type(exc).__name__}: {str(exc)[:110]}")
    print()


run("conservative-L2", gb_f * math.sqrt(COLS))
run("optimistic-Linf-as-L2", gb_f)

print("VERDICT: the two mappings differ by a factor sqrt(3904) ~= 62.5 in the")
print("norm bound, which dominates any bit-security number. The conservative one")
print("is past q (no answer); the optimistic one overstates security. Neither is")
print("derived from Gao. Until the ring-relation -> integer-SIS norm mapping is")
print("settled by a lattice cryptographer, NO certified bit-security is claimed.")
print("PROBE_DONE")
