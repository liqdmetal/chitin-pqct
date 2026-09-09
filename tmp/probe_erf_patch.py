"""Unblock the estimator's norm=oo path by replacing its broken erf call.

ROOT CAUSE (from the real traceback):
  estimator/prob.py:92  gaussian_cdf ->
    RR((1/2)*(1 + erf((t - mu)/(sqrt(2)*sigma))))
  Sage's SYMBOLIC erf evaluates through sage.libs.mpmath.utils.mpfr_from_mpfval,
  which does `sign, man, exp, _ = x` on an mpf tuple backed by gmpy2 and dies:
    TypeError: Cannot convert mpz to sage.rings.integer.Integer
  This is an mpmath<->sage bridge bug in the conda-forge build, NOT our input.
  It only affects the norm=oo path, because that path calls gaussian_cdf.

FIX ATTEMPTED HERE: monkeypatch gaussian_cdf to use stdlib math.erf (libm
double precision). A lattice security estimate needs ~2 significant digits;
float64 gives ~16. The patch keeps the RR() return type so downstream code
sees the same parent.

WHY norm=oo MATTERS: Gao's gamma_bin = 1.4318e14 is an L-INFINITY
(coefficientwise) bound and is ALREADY < q = 5.6295e14, so it is well-posed
as an inf-norm instance and needs NO sqrt(cols) inflation. The inflation is
what pushed the conservative L2 mapping past q ("trivially easy").

If this works we get the FIRST real verified bit-security number for the
paper profile. If it does not, we report that honestly and the blocker stays
open on the environment.
"""

import math
import sys
import traceback
from decimal import Decimal

import estimator.prob as prob
from estimator import SIS
from estimator.reduction import ADPS16, BDGL16, MATZOV
from sage.all import ZZ, RR, oo

sys.path.insert(0, "/mnt/c/Users/officeone/pq-ct-research")
from pqct.paper_bounds import gamma_bin_reduced

print("=== original gaussian_cdf ===")
import inspect
print(inspect.getsource(prob.gaussian_cdf))

# --- monkeypatch: stdlib erf, same signature, same RR return parent ---
_orig = prob.gaussian_cdf


def gaussian_cdf_fixed(t, sigma=1.0, mu=0.0):
    """P[X <= t] for X ~ N(mu, sigma^2), using libm erf (float64)."""
    if sigma == 0:
        return RR(1) if t >= mu else RR(0)
    return RR(0.5 * (1.0 + math.erf((float(t) - float(mu)) / (math.sqrt(2.0) * float(sigma)))))


prob.gaussian_cdf = gaussian_cdf_fixed
# Some modules import the symbol directly; patch those references too.
for mod in list(sys.modules.values()):
    if hasattr(mod, "gaussian_cdf") and getattr(mod, "gaussian_cdf", None) is _orig:
        try:
            setattr(mod, "gaussian_cdf", gaussian_cdf_fixed)
        except Exception:
            pass

print("=== patched gaussian_cdf sanity ===")
for t, s in ((0, 1), (1.96, 1), (-2, 1), (3, 1)):
    print(f"  gaussian_cdf({t}, sigma={s}) = {float(prob.gaussian_cdf(t, s)):.10f}")
print()

Q = 2 ** 49 - 2 ** 18 + 2 ** 9 + 1
N_MODULE, D, S, COLS = 29, 64, 2, 3904
gb = gamma_bin_reduced(8, D, 56, 64, S, Decimal(15), Decimal(15), 1, 60)
print(f"gamma_bin(reduced, L-inf bound) = {gb:.6e}")
print(f"q                              = {float(Q):.6e}")
print(f"gamma_bin < q (well-posed as INF-NORM instance) ? {gb < Q}")
print()

MODELS = (("ADPS16", ADPS16()), ("BDGL16", BDGL16()), ("MATZOV", MATZOV()))

print("=== norm=oo (INF-NORM bound passed directly, NO inflation) ===")
results = {}
for name, model in MODELS:
    try:
        p = SIS.Parameters(n=ZZ(N_MODULE), q=ZZ(Q), length_bound=gb,
                           m=ZZ(COLS), norm=oo, tag="paper-oo")
        cost = SIS.estimate(p, red_cost_model=model, jobs=1,
                            catch_exceptions=False, quiet=True)
        node = cost.get("lattice") if isinstance(cost, dict) else cost
        node = node if isinstance(node, dict) else cost
        rop = float(node["rop"]) if "rop" in node else None
        bkz = float(node["bkz"]) if "bkz" in node else None
        bits = math.log2(rop) if rop and rop > 0 else None
        results[name] = (rop, bits, bkz)
        print(f"  {name:7s} -> rop={rop:.6e}  log2(rop)={bits:.2f} bits  bkz={bkz}")
    except Exception as exc:
        print(f"  {name:7s} -> FAIL {type(exc).__name__}: {str(exc)[:160]}")
        traceback.print_exc(limit=3)
print()

if results:
    bits_all = [b for (_, b, _) in results.values() if b is not None]
    if bits_all:
        print(f"VERIFIED SECURITY RANGE: {min(bits_all):.2f} - {max(bits_all):.2f} bits (rop)")
        print(f"  quantum (MATZOV): {results.get('MATZOV', (None,None,None))[1]}")
        print(f"  classical min:    {min(v[1] for k,v in results.items() if 'MATZOV' not in k)}")
print("PROBE_DONE")
