from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.protocol1_sampling import Protocol1DistributionParameters
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
    return (
        params, base, e, e, base, commitments, bits, openings,
        Protocol1DistributionParameters(B=1, gaussian_tail=8, phi1=1, phi2=2),
        RingProtocol1Parameters(2, 1, 1000000, 1000000, 1000000),
        unit, unit,
    )


def _marginal_dict(stats):
    if stats is None:
        return None
    return {
        "left_count": stats.left_count,
        "right_count": stats.right_count,
        "left_mean": str(stats.left_mean),
        "right_mean": str(stats.right_mean),
        "left_variance": str(stats.left_variance),
        "right_variance": str(stats.right_variance),
        "distinct_values": stats.distinct_values,
        "exact_tv": str(stats.exact_tv),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded fixed-challenge comparison")
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--seed", default="shvzk-cli")
    args = parser.parse_args()
    _, base, e, f, g, commitments, bits, openings, distribution, proof_params, zeta, x = build_fixture()
    result = compare_fixed_challenge(
        args.seed.encode(), b"shvzk-cli-statement", base, e, f, g,
        commitments, bits, openings, 1, 2, distribution, proof_params,
        zeta, x, args.samples,
    )
    response_digest, transcript_digest = result.digest_stats(2)
    print(json.dumps({
        "samples": result.samples,
        "honest_acceptance_rate": str(result.honest_acceptance_rate),
        "simulator_acceptance_rate": str(result.simulator_acceptance_rate),
        "response_tv": str(result.response_tv),
        "transcript_tv": str(result.transcript_tv),
        "response_prefix_tv_2_bytes": str(result.response_stats.exact_histogram_tv),
        "transcript_prefix_tv_2_bytes": str(result.transcript_stats.exact_histogram_tv),
        "response_digest_tv_2_bytes": str(response_digest.exact_histogram_tv),
        "transcript_digest_tv_2_bytes": str(transcript_digest.exact_histogram_tv),
        "response_digest_collision_left": str(response_digest.collision_probability_left),
        "response_digest_collision_right": str(response_digest.collision_probability_right),
        "honest_rejection_rate": str(result.honest_rejection_rate),
        "simulator_rejection_rate": str(result.simulator_rejection_rate),
        "honest_mean_log_acceptance": str(result.honest_mean_log_acceptance),
        "simulator_mean_log_acceptance": str(result.simulator_mean_log_acceptance),
        "conditioned_response_tv": str(result.conditioned_response_tv),
        "conditioned_transcript_tv": str(result.conditioned_transcript_tv),
        "marginal_g": _marginal_dict(result.marginal_g_stats),
        "marginal_zg": _marginal_dict(result.marginal_zg_stats),
        "marginal_zb": _marginal_dict(result.marginal_zb_stats),
    }, indent=2))


if __name__ == "__main__":
    main()
