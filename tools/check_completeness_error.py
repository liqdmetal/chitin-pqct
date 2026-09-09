"""Lemma 6 completeness-error validation: measured acceptance vs 1/(mu1*mu2).

Gao Theorem 1/2 claim SHVZK "with a completeness error 1-1/(mu(phi_1)mu(phi_2))"
defined in Lemma 6 -- i.e. the honest prover's ACCEPTANCE PROBABILITY should be
1/(mu(phi_1)*mu(phi_2)) (up to the paper's 2^-100 statistical distance and the
finite-support approximation used here).

This is a quantitative, falsifiable prediction about the harness, not a
restatement: we measure the real acceptance rate over many samples and test it
against the formula with a normal-approximation confidence interval.

Synthetic research diagnostic. Finite-support reference Gaussians; agreement
with the formula is NOT a proof of Lemma 6, SHVZK, or any security claim.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.paper_bounds import mu_phi
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.protocol1_shvzk_compare import compare_fixed_challenge
from pqct.ring_commitment import ToyParameters


def predicted_acceptance(phi1: Decimal, phi2: Decimal) -> Decimal:
    """Lemma 6 / Theorem 1: honest acceptance probability 1/(mu(phi1)*mu(phi2))."""
    return Decimal(1) / (mu_phi(phi1) * mu_phi(phi2))


def wilson_interval(accepts: int, trials: int, z: Decimal = Decimal("1.96")) -> tuple[Decimal, Decimal]:
    """Wilson score interval for a binomial proportion (z=1.96 -> ~95%)."""
    if trials <= 0:
        raise ValueError("trials must be positive")
    n = Decimal(trials)
    p_hat = Decimal(accepts) / n
    z2 = z * z
    denom = Decimal(1) + z2 / n
    centre = (p_hat + z2 / (Decimal(2) * n)) / denom
    margin = (z / denom) * ((p_hat * (Decimal(1) - p_hat) / n + z2 / (Decimal(4) * n * n)).sqrt())
    return (max(Decimal(0), centre - margin), min(Decimal(1), centre + margin))


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
    proof_params = RingProtocol1Parameters(2, 1, 1000000, 1000000, 1000000)
    return base, e, e, base, commitments, bits, openings, proof_params, unit, unit


def main() -> None:
    parser = argparse.ArgumentParser(description="Lemma 6 completeness-error validation")
    parser.add_argument("--samples", type=int, default=2000)
    parser.add_argument("--phis", default="1,2,4,8")
    args = parser.parse_args()
    phis = [Decimal(value.strip()) for value in args.phis.split(",")]

    base, e, f, g, commitments, bits, openings, proof_params, zeta, x = build_fixture()

    rows = []
    all_consistent = True
    for phi1 in phis:
        phi2 = Decimal("2")
        distribution = Protocol1DistributionParameters(
            B=1, gaussian_tail=12, phi1=phi1, phi2=phi2, auto_tail=True,
        )
        result = compare_fixed_challenge(
            b"lemma6-seed", b"lemma6-statement", base, e, f, g,
            commitments, bits, openings, 1, 2, distribution, proof_params,
            zeta, x, args.samples,
        )
        trials = result.samples
        accepts = result.honest_accepts
        lo, hi = wilson_interval(accepts, trials)
        predicted = predicted_acceptance(phi1, phi2)
        covered = lo <= predicted <= hi
        all_consistent = all_consistent and covered
        rows.append({
            "phi1": str(phi1),
            "phi2": str(phi2),
            "trials": trials,
            "accepts": accepts,
            "measured_rate": str(Decimal(accepts) / Decimal(trials)),
            "predicted_1_over_mu_mu": str(predicted),
            "wilson95_low": str(lo),
            "wilson95_high": str(hi),
            "predicted_inside_ci": covered,
        })

    print(json.dumps({
        "warning": (
            "finite-support reference sampler; agreement with 1/(mu1*mu2) is "
            "consistency with Lemma 6's claimed completeness error, NOT a "
            "proof of it and not a security claim"
        ),
        "samples_per_phi": args.samples,
        "rows": rows,
        "all_phis_consistent": all_consistent,
    }, indent=2))


if __name__ == "__main__":
    main()
