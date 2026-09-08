"""Chi-square goodness-of-fit: do t_i mask samples fit their claimed law?

Direct test of pqct.protocol1_sampling.sample_protocol1_masks output
against FiniteDiscreteGaussian(phi1*T1, tail) -- the EXACT claimed law
for t_i, unlike g=x*b+t (shifted) or z_g=x*r_e+r_f (mixed), t_i is
sampled directly from that profile with no further transformation, so
this is the cleanest falsifiable test available in this codebase.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decimal import Decimal

from pqct.goodness_of_fit import chi_square_goodness_of_fit
from pqct.hmc import centered_coefficients
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.protocol1_sampling import XofByteSource
from pqct.protocol1_sampling import sample_protocol1_masks
from pqct.ring_commitment import ToyParameters


def main() -> None:
    params = ToyParameters(n=32, q=12289, k=2)
    distribution = Protocol1DistributionParameters(
        B=1, gaussian_tail=12, phi1=Decimal("2.0"), phi2=Decimal("4.0"),
    )
    p, w, k, m, d = 2, 4, 6, 2, params.n
    t_profile, _, t1, _ = distribution.profiles(p, w, k, m, d)

    source = XofByteSource(b"gof-mask-check-seed")
    samples_needed = 20000
    coefficients: list[int] = []
    while len(coefficients) < samples_needed:
        masks = sample_protocol1_masks(
            source, params, vector_count=2, bit_width=k,
            randomness_width=m, p=p, w=w, distribution=distribution,
        )
        for row in masks.t:
            for element in row:
                coefficients.extend(centered_coefficients(element))
    coefficients = coefficients[:samples_needed]

    observed: dict[int, int] = {}
    for value in coefficients:
        observed[value] = observed.get(value, 0) + 1

    weights = t_profile.weights
    total_weight = t_profile.total_weight
    expected = {
        value: weight / total_weight
        for value, weight in zip(t_profile.support, weights)
    }

    result = chi_square_goodness_of_fit(observed, expected, min_expected=5.0)
    print(json.dumps({
        "warning": (
            "tests the FINITE reference sampler against its OWN claimed "
            "PMF; does not establish agreement with Gao's exact infinite "
            "D_sigma law or the paper's 2^-100 statistical-distance target"
        ),
        "sigma": str(t_profile.sigma),
        "tail": t_profile.tail,
        "t1": str(t1),
        "samples": len(coefficients),
        "bins_used": result.bins_used,
        "merged_low_expected_bins": result.merged_low_expected_bins,
        "chi_square_statistic": result.statistic,
        "degrees_of_freedom": result.degrees_of_freedom,
        "p_value": result.p_value,
        "verdict": (
            "FAILS to reject fit (p>=0.01)" if result.p_value >= 0.01
            else "REJECTS fit (p<0.01) -- sampler does not match its own claimed law"
        ),
    }, indent=2))


if __name__ == "__main__":
    main()
