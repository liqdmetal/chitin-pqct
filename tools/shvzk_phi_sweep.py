"""SHVZK rejection-flattening sweep: does Rej actually flatten the witness shift?

The sharp test. Honest g = x*b + t at a bit=1 position carries a +x shift
per coefficient. Lyubashevsky rejection (stage 1, shift c = x*b) reweights
the mask so the ACCEPTED g has mean ~0 -- matching the simulator, which
samples g ~ D_{1,T1} directly. If stage-1 rejection were miswired, the
accepted honest mean would sit near the raw shift (+1 per coefficient for
x = unit) instead of 0.

Measured per phi1:
  - accepted honest mean at a bit=1 position  (expect ~0, NOT ~+1)
  - simulator mean at the same position      (expect ~0)
  - standardized mean-gap z-score            (expect |z| within noise)
  - acceptance rate                          (expect increasing with phi1,
                                              ~1/(mu(phi1)*mu(phi2)))
A bit=0 position is measured as the no-shift control.

Synthetic research diagnostic. Consistency with Lemma 6's mechanism is not
a proof of SHVZK or any security claim.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.hmc import HMCKey, bounded_ring_element, centered_coefficients
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.protocol1_shvzk_compare import compare_fixed_challenge
from pqct.ring_commitment import ToyParameters


def build_fixture():
    """Fixture where bits[0] = (0, 1): position (0,1) bears the witness."""
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
    # x = unit: the witness shift at a bit=1 position is +1 on coefficient 0.
    return params, base, e, e, base, commitments, bits, openings, proof_params, unit, unit


def run_position(base, e, f, g, commitments, bits, openings, proof_params, zeta, x,
                 phi1, position, samples, seed):
    distribution = Protocol1DistributionParameters(
        B=1, gaussian_tail=12, phi1=phi1, phi2=Decimal("2"), auto_tail=True,
    )
    result = compare_fixed_challenge(
        seed, b"flatten-statement", base, e, f, g,
        commitments, bits, openings, 1, 2, distribution, proof_params,
        zeta, x, samples, g_position=position,
    )
    stats = result.marginal_g_stats
    row = {
        "phi1": str(phi1),
        "position": list(position),
        "accepts": result.honest_accepts,
        "acceptance_rate": str(result.honest_acceptance_rate),
    }
    if stats is None or stats.left_count == 0:
        row["error"] = "no accepted honest samples"
        return row
    n_left = stats.left_count
    n_right = stats.right_count
    var_left = stats.left_variance
    var_right = stats.right_variance
    gap = stats.left_mean - stats.right_mean
    se = (var_left / n_left + var_right / n_right).sqrt()
    row.update({
        "honest_mean": str(stats.left_mean),
        "simulator_mean": str(stats.right_mean),
        "mean_gap": str(gap),
        "gap_z_score": str(gap / se if se > 0 else Decimal("NaN")),
        "exact_tv": str(stats.exact_tv),
        "n_honest_coeffs": n_left,
    })
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description="rejection-flattening sweep")
    parser.add_argument("--samples", type=int, default=400)
    parser.add_argument("--phis", default="1,2,4,8")
    args = parser.parse_args()
    phis = [Decimal(value.strip()) for value in args.phis.split(",")]

    _, base, e, f, g, commitments, bits, openings, proof_params, zeta, x = build_fixture()

    witness_rows = []
    control_rows = []
    for phi1 in phis:
        witness_rows.append(run_position(
            base, e, f, g, commitments, bits, openings, proof_params, zeta, x,
            phi1, (0, 1), args.samples, b"flatten-witness-seed",
        ))
        control_rows.append(run_position(
            base, e, f, g, commitments, bits, openings, proof_params, zeta, x,
            phi1, (0, 0), args.samples, b"flatten-control-seed",
        ))

    def flattened(rows):
        """True if every honest mean is closer to 0 than the raw +1 shift."""
        for row in rows:
            if "honest_mean" not in row:
                return False
            if abs(Decimal(row["honest_mean"])) >= Decimal("0.5"):
                return False
        return True

    print(json.dumps({
        "warning": (
            "synthetic finite-sample diagnostic; mean-flattening consistency "
            "with Lemma 6's mechanism is NOT a proof of SHVZK"
        ),
        "criterion": (
            "accepted honest mean at bit=1 position must be ~0 (flattened), "
            "not ~+1 (raw witness shift); |z| within finite-sample noise"
        ),
        "witness_position_0_1": witness_rows,
        "control_position_0_0": control_rows,
        "witness_means_flattened": flattened(witness_rows),
        "acceptance_increases_with_phi": [r["accepts"] for r in witness_rows],
    }, indent=2))


if __name__ == "__main__":
    main()
