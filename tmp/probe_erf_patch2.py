"""Second attempt at unblocking the estimator's norm=oo path.

Two bugs in the PREVIOUS probe, both mine:
  1. The real signature is gaussian_cdf(mu, sigma, t). My patch declared
     (t, sigma, mu), so every estimator call was argument-scrambled. The
     patch's "sanity check" passed only because it was called with the
     same wrong convention.
  2. length_bound was passed as a Decimal (gamma_bin), which is the likely
     source of "TypeError: argument must be an integer" from batch_estimate.
     The one norm=oo call that ever reached gaussian_cdf used ZZ(64).

Root cause being worked around (unchanged, from the real traceback):
  estimator/prob.py gaussian_cdf ->
    RR((1/2)*(1 + erf((t - mu)/(sqrt(2)*sigma))))
  Sage's symbolic erf evaluates via sage.libs.mpmath.utils.mpfr_from_mpfval,
  which unpacks an mpf tuple backed by gmpy2 and dies with
  "Cannot convert mpz to sage.rings.integer.Integer". Conda-build bridge bug.
"""

import inspect
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

print("=== real signature (must match exactly) ===")
print(inspect.signature(prob.gaussian_cdf))

_orig = prob.gaussian_cdf


def gaussian_cdf_fixed(mu, sigma, t):
    """Pr[X <= t] for X ~ N(mu, sigma^2), libm erf in float64.

    Argument order matches the real function: (mu, sigma, t).
    """
    mu = float(mu)
    sigma = float(sigma)
    t = float(t)
    if sigma == 0:
        return RR(1) if t >= mu else RR(0)
    return RR(0.5 * (1.0 + math.erf((t - mu) / (math.sqrt(2.0) * sigma))))


prob.gaussian_cdf = gaussian_cdf_fixed
patched = []
for name, mod in list(sys.modules.items()):
    if mod is None or name == "__main__":
        continue
    try:
        if getattr(mod, "gaussian_cdf", None) is _orig:
            setattr(mod, "gaussian_cdf", gaussian_cdf_fixed)
            patched.append(name)
    except Exception:
        pass
print("patched modules:", patched or "(none beyond estimator.prob)")

print()
print("=== sanity in the REAL convention (mu, sigma, t) ===")
cases = ((0, 1, 0), (0, 1, 1.96), (0, 1, -2), (5, 2, 5))
for mu, sigma, t in cases:
    print(f"  gaussian_cdf(mu={mu}, sigma={sigma}, t={t}) = "
          f"{float(prob.gaussian_cdf(mu, sigma, t)):.10f}")

Q = 2 ** 49 - 2 ** 18 + 2 ** 9 + 1
N_MODULE, D, S, COLS = 29, 64, 2, 3904
gb = gamma_bin_reduced(8, D, 56, 64, S, Decimal(15), Decimal(15), 1, 60)
gb_int = int(gb)
print()
print(f"gamma_bin(reduced, L-inf) = {gb:.6e}   as int = {gb_int}")
print(f"q                        = {float(Q):.6e}")
print(f"gamma_bin < q            ? {gb < Q}")

MODELS = (("ADPS16", ADPS16()), ("BDGL16", BDGL16()), ("MATZOV", MATZOV()))

print()
print("=== norm=oo, length_bound as ZZ INTEGER (both fixes applied) ===")
results = {}
for name, model in MODELS:
    try:
        p = SIS.Parameters(n=ZZ(N_MODULE), q=ZZ(Q), length_bound=ZZ(gb_int),
                           m=ZZ(COLS), norm=oo, tag="paper-oo")
        print(f"  [{name}] params.norm = {p.norm}, length_bound = {p.length_bound}")
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
        print(f"  {name:7s} -> FAIL {type(exc).__name__}: {str(exc)[:150]}")
        traceback.print_exc(limit=2)
print()

if results:
    bits_all = [b for (_, b, _) in results.values() if b is not None]
    if bits_all:
        print(f"VERIFIED RANGE: {min(bits_all):.2f} - {max(bits_all):.2f} bits (rop)")
print("PROBE_DONE")
