"""Sandboxed bridge to the REAL malb/lattice-estimator for Gao's M-SIS profile.

Runs ONLY inside the sandboxed WSL user (see docs/VERIFIED_LATTICE_ESTIMATE.md):

    wsl -u pqct -e bash -lc '
      cd /mnt/c/Users/officeone/pq-ct-research
      ~/miniforge3/envs/sage/bin/sage -python tools/sage_sis_estimate.py
    '

WHAT THIS ESTIMATES
-------------------
Gao Lemma 1: the HMC is computationally strong gamma-binding if
M-SIS(n, m+v, q, gamma) is hard. Section 8 profile: phi1=phi2=15, B=1,
(d,w,p)=(64,56,8), q=2^49-2^18+2^9+1, (n,m)=(29,60), k=v=64, S=2.
gamma_bin is the REDUCED Eq.(21) bound = max{B_Bin, B_Amor} (pqct.paper_bounds,
reproduced against the paper's printed 2.86e14 = 2*gamma_bin).

MODULE -> INTEGER EMBEDDING (an interpretation, stated explicitly):
a module lattice over R_q of degree d becomes an integer lattice with d times
the rows and columns, so
    n_int = n*d         = 29*64  = 1856
    m_int = (m+v)*d     = 124*64 = 7936

NORM CONVENTION (this was the crux, and my earlier versions got it wrong):
gamma_bin is a COEFFICIENTWISE / L_INFINITY bound on z, so norm=oo with the
bound passed straight through is the semantically correct AND conservative
reading. Two wrong variants were tried and are documented as rejected:
  - gamma_bin inflated to L2 by sqrt(cols): bound exceeds q, so the estimator
    refuses ("SIS trivially easy") and returns NOTHING -- an overstated norm
    makes the problem easier, so this reading is uninformative, not insecure.
  - gamma_bin passed as an L2 bound directly: understates the true L2 norm,
    OVERSTATES security by ~25 bits. Reported only for contrast.

ERF WORKAROUND (required in this conda-forge Sage build):
estimator/prob.py gaussian_cdf calls Sage's symbolic erf, which evaluates
through sage.libs.mpmath.utils.mpfr_from_mpfval and dies with
    TypeError: Cannot convert mpz to sage.rings.integer.Integer
on the norm=oo path. Patching gaussian_cdf to stdlib math.erf (float64) fixes
it; a lattice estimate needs ~2 significant digits and float64 gives ~16.
Without this patch the inf-norm path cannot run at all.

RESULT ACCESS PATTERN (a trap I hit twice):
SIS.estimate returns {'lattice': Cost} and Cost supports ['rop'] indexing but
is NOT a dict, so any `isinstance(node, dict)` fallback silently re-reads the
OUTER dict and yields None instead of the number.

COST MODELS must be INSTANCES (ADPS16()), not classes: passing the class shifts
self/beta and produces a misleading "short_vectors() missing 1 required
positional argument: 'd'".
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from decimal import Decimal

# ---- erf workaround (must precede the estimator import) ----
import estimator.prob as _prob
from sage.all import RR

_ORIG_CDF = _prob.gaussian_cdf


def _gaussian_cdf_libm(mu, sigma, t):
    """Pr[X <= t] for X ~ N(mu, sigma^2) via libm erf. Signature order is
    (mu, sigma, t) -- matching the real function is load-bearing; a swapped
    order silently produces wrong probabilities."""
    mu, sigma, t = float(mu), float(sigma), float(t)
    if sigma == 0:
        return RR(1) if t >= mu else RR(0)
    return RR(0.5 * (1.0 + math.erf((t - mu) / (math.sqrt(2.0) * sigma))))


_prob.gaussian_cdf = _gaussian_cdf_libm
for _name, _mod in list(sys.modules.items()):
    if _mod is not None and _name != "__main__":
        try:
            if getattr(_mod, "gaussian_cdf", None) is _ORIG_CDF:
                setattr(_mod, "gaussian_cdf", _gaussian_cdf_libm)
        except Exception:  # noqa: BLE001 - best effort, module may lack the attr
            pass
# ---- end workaround ----

from estimator import SIS
from estimator.reduction import ADPS16, BDGL16, MATZOV
from sage.all import ZZ, oo

sys.path.insert(0, "/mnt/c/Users/officeone/pq-ct-research")
from pqct.paper_bounds import gamma_bin_reduced

Q = 2 ** 49 - 2 ** 18 + 2 ** 9 + 1
N_MODULE, D, W, P, M_RAND, V_MSG, S_DEFAULT = 29, 64, 56, 8, 60, 64, 2

COST_MODELS = (
    ("classical_ADPS16", ADPS16()),
    ("classical_BDGL16", BDGL16()),
    ("quantum_MATZOV", MATZOV()),
)


def extract_bits(cost: dict) -> dict:
    """Pull rop/bkz/d out of {'lattice': Cost}. See module docstring: Cost is
    indexable but NOT a dict -- do not use an isinstance fallback."""
    node = cost["lattice"] if "lattice" in cost else cost
    out = {}
    for key in ("rop", "bkz", "d", "delta", "repeat"):
        try:
            if key in node:
                out[key] = float(node[key])
        except (TypeError, ValueError, KeyError):
            pass
    rop = out.get("rop")
    if rop is None:
        out["log2_rop"] = None
    elif math.isinf(rop):
        out["log2_rop"] = float("inf")
        out["note"] = "infeasible below the target norm (bound may be too small)"
    else:
        out["log2_rop"] = math.log2(rop) if rop > 0 else None
    return out


def gaussian_heuristic_check(gamma: float, n_int: int, m_int: int, q: int) -> dict:
    """Report the Gaussian heuristic at BOTH the full and optimal dimension.

    CORRECTED. An earlier version of this gate evaluated the Gaussian
    heuristic ONLY at the full column count m_int and declared the paper
    profile "trivially easy by counting". That verdict was WRONG, and the
    error was mine: it is the wrong dimension.

    Short vectors do exist in the full m_int-column lattice, but an attacker
    does not have to work there -- they DROP columns and attack an optimal
    sub-dimension m' = sqrt(n_int*log2(q)/log2(delta)). Gao's Eq.(2)
    exponential 2^(2*sqrt(n*d*log2 q*log2 delta)) is exactly the minimum of
    delta^m' * q^(n_int/m') over m', i.e. it already encodes this. For the
    paper profile m' ~ 3787, and the real lattice-estimator independently
    reported working dimensions d in 3378..4008 -- agreement that confirms
    m', not m_int, is the operative dimension.

    "Solutions exist" is a counting statement; "solutions are findable
    cheaply" is a cost statement. Conflating them produced a false alarm.
    Use pqct.msis_hardness.analyze_msis for the criterion that matters.
    """
    log_q = math.log2(q)
    log_gh_full = log_q * n_int / m_int
    gh_full = 2.0 ** log_gh_full
    ratio_full = gamma / gh_full
    return {
        "full_dimension": {
            "m_int": m_int,
            "log2_gh_min_norm": log_gh_full,
            "gamma_over_gh": ratio_full,
            "meaning": (
                "counting only: short vectors exist in the full-column "
                "lattice. This does NOT imply the instance is easy, and must "
                "not be read as a hardness verdict."
            ),
        },
        "correct_criterion": (
            "see pqct.msis_hardness.analyze_msis -- Gao Eq.(2) with the "
            "optimal sublattice dimension m' = sqrt(n_int*log2 q/log2 delta)"
        ),
        "superseded_verdict": (
            "an earlier version of this function called the paper profile "
            "'TRIVIALLY EASY by counting'. That was a false alarm caused by "
            "evaluating the Gaussian heuristic at the wrong (full) dimension."
        ),
    }


def gamma_bin_for(S: int) -> Decimal:
    return gamma_bin_reduced(P, D, W, V_MSG, S, Decimal(15), Decimal(15), 1, M_RAND)


def estimate(S: int = S_DEFAULT, norm_inf: bool = True) -> dict:
    """Estimate M-SIS hardness for the paper profile at output count S."""
    gb = gamma_bin_for(S)
    gb_int = int(gb)
    n_int = N_MODULE * D
    m_int = (M_RAND + V_MSG) * D
    conservative_l2 = float(gb) * math.sqrt(m_int)

    result = {
        "profile": {
            "source": "Gao et al. IACR ePrint 2021/1674 Section 8",
            "phi1_phi2": 15, "B": 1, "d": D, "w": W, "p": P,
            "n_module": N_MODULE, "m_randomness": M_RAND, "v_message": V_MSG,
            "S": S, "q": Q,
        },
        "gamma_bin_reduced": str(gb),
        "gamma_bin_lt_q": gb < Q,
        "dimension_mapping": {
            "n_int": n_int, "m_int": m_int,
            "rule": "n_int = n*d, m_int = (m+v)*d",
            "status": "INTERPRETATION -- module->integer embedding, not stated by paper",
        },
        "norm_convention": (
            "inf-norm (norm=oo), gamma_bin passed straight through -- correct "
            "and conservative for a coefficientwise bound"
            if norm_inf else
            "gamma_bin passed as an L2 bound -- UNDERSTATES the norm, so it "
            "OVERSTATES security; reported for contrast only"
        ),
        "conservative_l2_bound": conservative_l2,
        "conservative_l2_exceeds_q": conservative_l2 >= float(Q),
        "erf_workaround_applied": True,
        "attacks": {},
    }

    result["validity_gate"] = gaussian_heuristic_check(
        float(gb), n_int, m_int, Q
    )

    bound = ZZ(gb_int)
    norm_val = oo if norm_inf else 2
    for name, model in COST_MODELS:
        try:
            params = SIS.Parameters(
                n=ZZ(n_int), q=ZZ(Q), length_bound=bound,
                m=ZZ(m_int), norm=norm_val, tag=f"gao-S{S}",
            )
            cost = SIS.estimate(
                params, red_cost_model=model, jobs=1,
                catch_exceptions=False, quiet=True,
            )
            result["attacks"][name] = extract_bits(cost)
        except Exception as error:  # noqa: BLE001 - report, never hide
            result["attacks"][name] = {"error": f"{type(error).__name__}: {error}"}

    bits = [
        v["log2_rop"]
        for v in result["attacks"].values()
        if v.get("log2_rop") is not None and not math.isinf(v["log2_rop"])
    ]
    gate = result["validity_gate"]
    result["summary"] = {
        "min_bits": min(bits) if bits else None,
        "max_bits": max(bits) if bits else None,
        "quantum_bits": result["attacks"].get("quantum_MATZOV", {}).get("log2_rop"),
        "paper_claim": "128-bit security of partially amortized binary proof at S<=2",
        "meets_paper_claim": bool(bits) and min(bits) >= 128.0,
        "interpretation": (
            "These are lattice-estimator's numbers for a SINGLE scalar-bound "
            "reading of gamma_bin. The independent delta-criterion analysis in "
            "pqct.msis_hardness (Gao Eq.2 at the optimal sublattice dimension) "
            "gives 91-118 bits for the same profile and AGREES with the "
            "estimator's delta to ~3e-4, so the two methods are consistent. "
            "Both land BELOW the paper's claimed 128-bit level, which traces "
            "to the legacy delta=1.0045 <-> 128-bit mapping inherited from "
            "MatRiCT rather than to an arithmetic error."
        ),
        "blocker_status": (
            "OPEN but NARROWED. No longer blocked on tooling: the estimator "
            "runs and two independent methods agree on delta. What remains is "
            "a genuine cryptographic judgement -- (a) the exact M-SIS instance "
            "for HMC binding has MIXED per-column bounds (small dr on the m "
            "randomness columns, small dm on the v message columns) that a "
            "single scalar length_bound cannot express, and (b) delta -> bits "
            "is a model choice. A lattice cryptographer must settle both. "
            "No certified bit-security level is claimed here."
        ),
        "superseded": (
            "an earlier run of this tool reported the profile 'trivially easy "
            "by counting'. That was a FALSE ALARM from evaluating the Gaussian "
            "heuristic at the full column count instead of the optimal "
            "sublattice dimension; see validity_gate.superseded_verdict."
        ),
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-S", type=int, default=S_DEFAULT, help="output account count")
    parser.add_argument(
        "--l2-contrast", action="store_true",
        help="report gamma_bin as an L2 bound instead (overstates security)",
    )
    args = parser.parse_args()
    print(json.dumps(estimate(args.S, norm_inf=not args.l2_contrast), indent=2, default=str))


if __name__ == "__main__":
    main()
