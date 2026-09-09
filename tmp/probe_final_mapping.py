"""Decisive probe: correct M-SIS dimension mapping + honest norm handling.

Paper facts used (vendor/gao-2021-1674.txt):
  Definition 1: M-SIS(n, m, q, gamma): given A in R_q^{n x m}, find
                z in R_q^m with A z = 0 mod q and 0 < ||z|| <= gamma.
  HMC key (line 249-253): G = (G_r, G_m) in R_q^{n x (m+v)}, so the SIS
                matrix has n ROWS and m+v COLUMNS.
  Lemma 1 (line 285): "If M-SIS(n, m + v, q, gamma_2) is hard, then the HMC
                is computationally strong gamma-binding."
  Section-8 profile: n=29 (module rank), d=64 (ring degree), m=60
                (randomness width), v = message width, q=2^49-2^18+2^9+1,
                gamma_bin (Eq.21 reduced) = 1.4318e14.

Module -> integer embedding: a module lattice over R_q of degree d becomes an
INTEGER lattice with d times as many rows and columns:
    n_int = n*d = 29*64 = 1856
    m_int = (m+v)*d

norm convention: gamma_bin is a COEFFICIENTWISE (L_inf) bound on z. The
estimator's norm=2 path is the one that works in this build (norm=oo dies in
an upstream bracket bug: util.py `self._best.low` is None). Two readings are
tested and BOTH reported -- no flattering pick:
    (a) pass gamma_bin straight through as the L2 bound (treats z as having
        essentially one nonzero coefficient; UNDERSTATES the norm, so it
        OVERSTATES security)
    (b) convert conservatively ||z||_2 <= ||z||_inf * sqrt(m_int)
        (OVERSTATES the norm, so it UNDERSTATES security; may exceed q)

Access pattern fixed from the earlier probe: cost is
{'lattice': Cost} and rop is cost['lattice']['rop'], NOT cost['rop'].
"""

import math
import sys
from decimal import Decimal

import estimator.prob as prob
from sage.all import ZZ, RR, oo

# --- workaround for the conda-build erf/mpfr bug (real traceback in
#     docs/VERIFIED_LATTICE_ESTIMATE.md): sage symbolic erf -> mpmath ->
#     "Cannot convert mpz to sage.rings.integer.Integer".
_orig = prob.gaussian_cdf


def _cdf(mu, sigma, t):
    mu, sigma, t = float(mu), float(sigma), float(t)
    if sigma == 0:
        return RR(1) if t >= mu else RR(0)
    return RR(0.5 * (1.0 + math.erf((t - mu) / (math.sqrt(2.0) * sigma))))


prob.gaussian_cdf = _cdf
for _name, _mod in list(sys.modules.items()):
    if _mod is not None and _name != "__main__":
        try:
            if getattr(_mod, "gaussian_cdf", None) is _orig:
                setattr(_mod, "gaussian_cdf", _cdf)
        except Exception:
            pass

from estimator import SIS
from estimator.reduction import ADPS16, BDGL16, MATZOV

sys.path.insert(0, "/mnt/c/Users/officeone/pq-ct-research")
from pqct.paper_bounds import gamma_bin_reduced

Q = 2 ** 49 - 2 ** 18 + 2 ** 9 + 1
N_MOD, D, M_RAND, V_MSG = 29, 64, 60, 64
N_INT = N_MOD * D                       # 1856
COLS_INT = (M_RAND + V_MSG) * D          # (60+64)*64 = 7936

gb = gamma_bin_reduced(8, D, 56, V_MSG, 2, Decimal(15), Decimal(15), 1, M_RAND)
gb_int = int(gb)
gb_f = float(gb)

print("=== inputs (paper Section-8 profile, module->integer embedding) ===")
print(f"  gamma_bin (Eq.21 reduced)  = {gb:.6e}")
print(f"  q                          = {Q} = {float(Q):.6e}")
print(f"  gamma_bin < q              = {gb < Q}")
print(f"  n_int = n*d                = {N_MOD}*{D} = {N_INT}")
print(f"  m_int = (m+v)*d            = ({M_RAND}+{V_MSG})*{D} = {COLS_INT}")
print(f"  conservative L2 = gb*sqrt(m_int) = {gb_f*math.sqrt(COLS_INT):.6e}"
      f"   < q ? {gb_f*math.sqrt(COLS_INT) < float(Q)}")
print()

MODELS = (("ADPS16", ADPS16()), ("BDGL16", BDGL16()), ("MATZOV", MATZOV()))


def bits(cost):
    """cost is {'lattice': Cost}; Cost supports ['rop'] indexing but is NOT
    a dict, so an isinstance(node, dict) fallback silently re-reads the
    OUTER dict and yields None. Index directly.
    """
    node = cost["lattice"] if "lattice" in cost else cost
    rop = node["rop"] if "rop" in node else None
    try:
        rop_f = float(rop)
    except (TypeError, ValueError, KeyError):
        rop_f = None
    bkz = node["bkz"] if "bkz" in node else None
    dd = node["d"] if "d" in node else None
    if rop_f is None:
        return rop, None, bkz, dd
    if math.isinf(rop_f):
        return rop, float("inf"), bkz, dd
    return rop, math.log2(rop_f), bkz, dd


def run(label, length_bound, n_int, m_int, norm_val):
    print(f"=== {label}: n={n_int}, m={m_int}, norm={norm_val}, "
          f"length_bound={float(length_bound):.6e}")
    if float(length_bound) >= float(Q):
        print("    SKIP: bound >= q -> estimator reports 'trivially easy'.")
        print("    (an overstated norm bound makes the problem easier, so this")
        print("     reading yields NO information, not a security number)")
        print()
        return None
    for name, model in MODELS:
        try:
            p = SIS.Parameters(n=ZZ(n_int), q=ZZ(Q), length_bound=length_bound,
                               m=ZZ(m_int), norm=norm_val, tag=label)
            cost = SIS.estimate(p, red_cost_model=model, jobs=1,
                                catch_exceptions=False, quiet=True)
            rop, b, bkz, dd = bits(cost)
            print(f"    {name:7s} -> rop={rop}  log2={b}  bkz={bkz}  d={dd}")
        except Exception as exc:
            print(f"    {name:7s} -> FAIL {type(exc).__name__}: {str(exc)[:110]}")
    print()


# (a) gamma_bin passed straight through as the L2 bound
run("direct-gb-as-L2", ZZ(gb_int), N_INT, COLS_INT, 2)
# (b) conservative L_inf -> L2 conversion
run("conservative-L2", ZZ(int(gb_f * math.sqrt(COLS_INT))), N_INT, COLS_INT, 2)
# (c) inf-norm path (expected to hit the upstream bracket bug)
run("inf-norm", ZZ(gb_int), N_INT, COLS_INT, oo)

print("DONE")
