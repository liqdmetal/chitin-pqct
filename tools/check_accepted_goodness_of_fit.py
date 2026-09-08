"""Chi-square goodness-of-fit: do ACCEPTED honest g/z_g/z_b,i samples fit
Gao's own claimed law (paper text lines 2030-2031, Theorem 1 completeness)?

Paper's exact claim: "the distributions of g_i,j's and z_g,(z_b,i) are
statistically close to D_{1,T1}^d and D_{2,T2}^{md} respectively." This
is testable directly on ACCEPTED (post-Rej) samples with no shift/mix
correction, unlike the raw-mask t_i check in check_mask_goodness_of_fit.py.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decimal import Decimal

from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.goodness_of_fit import chi_square_goodness_of_fit
from pqct.hmc import HMCKey, bounded_ring_element, centered_coefficients
from pqct.protocol1_sampling import FiniteDiscreteGaussian, Protocol1DistributionParameters
from pqct.protocol1_shvzk_compare import compare_fixed_challenge
from pqct.ring_commitment import ToyParameters


def build_fixture():
    params = ToyParameters(n=8, q=12289, k=1)
    r = lambda values: bounded_ring_element(values, params)
    unit = r((1, 0, 0, 0, 0, 0, 0, 0))
    zero = r((0, 0, 0, 0, 0, 0, 0, 0))
    base = HMCKey(((unit,),), ((unit, r((0, 1, 0, 0, 0, 0, 0, 0))),), params)
    e = HMCKey(((unit,),), (tuple(unit for _ in range(4)),), params)
    bits = ((zero, unit), (unit, zero))
    openings = ((unit,), (r((2, 0, 0, 0, 0, 0, 0, 0)),))
    commitments = tuple(base.commit(vector, opening) for vector, opening in zip(bits, openings))
    distribution = Protocol1DistributionParameters(
        B=1, gaussian_tail=60, phi1=Decimal("1"), phi2=Decimal("2"),
    )
    proof_params = RingProtocol1Parameters(2, 1, 1000000, 1000000, 1000000)
    zeta = unit
    x = unit
    return params, base, e, e, base, commitments, bits, openings, distribution, proof_params, zeta, x


def _profile_expected(profile: FiniteDiscreteGaussian, extra_tail: int = 5) -> dict[int, Decimal]:
    """Expected PMF over an EXTENDED support (same sigma, wider tail).

    Observed z_g/z_b,i values can land at profile.tail+shift (the shift
    term from x*r_e or x*r_b,i), beyond profile.support's own truncation.
    Widening the enumerated support (same sigma, same normalization
    formula) avoids spurious 'missing support value' errors without
    changing the claimed law.
    """
    wide = FiniteDiscreteGaussian(profile.sigma, profile.tail + extra_tail)
    weights = wide.weights
    total = wide.total_weight
    return {value: weight / total for value, weight in zip(wide.support, weights)}


def main() -> None:
    (params, base, e, f, g, commitments, bits, openings,
     distribution, proof_params, zeta, x) = build_fixture()
    p, w = 1, 2
    width = len(bits[0])
    result = compare_fixed_challenge(
        b"accepted-gof-seed", b"accepted-gof-statement", base, e, f, g,
        commitments, bits, openings, p, w, distribution, proof_params,
        zeta, x, 250,
    )
    t_profile, opening_profile, t1, t2 = distribution.profiles(
        p, w, width, base.randomness_width, params.n,
    )

    def run(name: str, samples, profile):
        if not samples:
            return {"name": name, "error": "no accepted honest samples"}
        observed: dict[int, int] = {}
        for value in samples:
            observed[value] = observed.get(value, 0) + 1
        expected = _profile_expected(profile)
        try:
            fit = chi_square_goodness_of_fit(observed, expected, min_expected=5.0)
        except Exception as error:  # noqa: BLE001 -- report, don't hide
            return {"name": name, "samples": len(samples), "error": str(error)}
        return {
            "name": name,
            "samples": len(samples),
            "sigma": str(profile.sigma),
            "bins_used": fit.bins_used,
            "degrees_of_freedom": fit.degrees_of_freedom,
            "chi_square_statistic": fit.statistic,
            "p_value": fit.p_value,
            "verdict": (
                "FAILS to reject fit (p>=0.01)" if fit.p_value >= 0.01
                else "REJECTS fit (p<0.01)"
            ),
        }

    print(json.dumps({
        "warning": (
            "tests ACCEPTED honest g/z_g/z_b,i samples against Gao's OWN "
            "claimed D_{1,T1}/D_{2,T2} law (paper text lines 2030-2031, "
            "Theorem 1 completeness); this is the paper's actual claim, "
            "not a self-consistency check of the sampler alone -- but it "
            "is still a finite-support/toy-parameter experiment, not a "
            "proof of the paper's 2^-100 statistical-distance target"
        ),
        "honest_accepts": result.honest_accepts,
        "samples_requested": result.samples,
        "g": run("g (claimed D_{1,T1})", result.honest_g_samples, t_profile),
        "z_g": run("z_g (claimed D_{2,T2})", result.honest_zg_samples, opening_profile),
        "z_b,i": run("z_b,i (claimed D_{2,T2})", result.honest_zb_samples, opening_profile),
    }, indent=2))


if __name__ == "__main__":
    main()

