"""Proving/verification throughput benchmark for Gao Protocol 1 (research only)."""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass, asdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqct.binary_protocol1_ring import RingProtocol1Parameters, verify_protocol1_ring
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.matrix_generation import generate_hmc_key
from pqct.parameterization import candidate_set
from pqct.protocol1_sampled import SampledProtocol1Error, prove_protocol1_ring_sampled
from pqct.protocol1_shvzk_compare import encode_response_tuple
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.ring_commitment import ToyParameters
from decimal import Decimal



@dataclass(frozen=True)
class BenchResult:
    candidate: str
    ring_n: int
    ring_q: int
    vector_count: int
    bit_width: int
    randomness_width: int
    attempts_used: int
    accepted: bool
    prove_seconds: float
    verify_seconds: float
    proof_bytes: int


def _fixture(candidate, vector_count: int, bit_width: int):
    params = ToyParameters(n=candidate.n, q=candidate.q, k=2)
    r = lambda values: bounded_ring_element(values, params)
    seed = b"bench-" + candidate.name.encode()
    randomness_width = 2
    base_key = generate_hmc_key(seed + b"-base", params, randomness_width, bit_width)
    key_e = generate_hmc_key(seed + b"-e", params, randomness_width, vector_count * bit_width)
    key_g = base_key
    bits = tuple(
        tuple(r((i % 2,) + (0,) * (candidate.n - 1)) for i in range(bit_width))
        for _ in range(vector_count)
    )
    openings = tuple(
        tuple(r((j + 1,) + (0,) * (candidate.n - 1)) for j in range(randomness_width))
        for _ in range(vector_count)
    )
    commitments = tuple(
        base_key.commit(row, opening) for row, opening in zip(bits, openings)
    )
    return params, base_key, key_e, key_g, bits, openings, commitments, randomness_width


def run_one(candidate, vector_count: int, bit_width: int, max_attempts: int) -> BenchResult:
    params, base_key, key_e, key_g, bits, openings, commitments, randomness_width = _fixture(
        candidate, vector_count, bit_width,
    )
    key_f = key_e
    p, w = 2, min(4, candidate.n)
    distribution = Protocol1DistributionParameters(
        B=1, gaussian_tail=8,
        phi1=Decimal(str(candidate.sigma_mask)),
        phi2=Decimal(str(candidate.sigma_opening)),
    )

    proof_params = RingProtocol1Parameters.from_paper_bounds(
        challenge_weight=w, challenge_coefficient_bound=1,
        B=1, p=p, k=vector_count, m=randomness_width, d=candidate.n,
        phi1=distribution.phi1, phi2=distribution.phi2,
        max_vectors=vector_count,
    )
    seed = b"bench-run-" + candidate.name.encode()
    t0 = time.perf_counter()
    try:
        sampled = prove_protocol1_ring_sampled(
            seed, b"bench-statement", base_key, key_e, key_f, key_g,
            commitments, bits, openings, p, w, distribution, proof_params,
            max_attempts=max_attempts,
        )
    except SampledProtocol1Error:
        prove_seconds = time.perf_counter() - t0
        return BenchResult(candidate.name, candidate.n, candidate.q, vector_count, bit_width, randomness_width, max_attempts, False, prove_seconds, 0.0, 0)
    prove_seconds = time.perf_counter() - t0

    t1 = time.perf_counter()
    ok = verify_protocol1_ring(
        b"bench-statement", base_key, key_e, key_f, key_g,
        commitments, sampled.proof, proof_params,
    )
    verify_seconds = time.perf_counter() - t1

    proof_bytes = len(encode_response_tuple(sampled.proof))
    return BenchResult(
        candidate.name, candidate.n, candidate.q, vector_count, bit_width,
        randomness_width, sampled.attempts, ok, prove_seconds, verify_seconds, proof_bytes,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Bench Gao Protocol 1 prove/verify")
    parser.add_argument("--vectors", type=int, default=2)
    parser.add_argument("--bit-width", type=int, default=4)
    parser.add_argument("--max-attempts", type=int, default=256)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()

    output = []
    for candidate in candidate_set():
        prove_times = []
        verify_times = []
        proof_bytes = None
        accepted_any = False
        attempts_last = 0
        for _ in range(args.repeats):
            result = run_one(candidate, args.vectors, args.bit_width, args.max_attempts)
            if result.accepted:
                accepted_any = True
                prove_times.append(result.prove_seconds)
                verify_times.append(result.verify_seconds)
                proof_bytes = result.proof_bytes
                attempts_last = result.attempts_used
        entry = {
            "candidate": candidate.name,
            "n": candidate.n,
            "q": candidate.q,
            "vectors": args.vectors,
            "bit_width": args.bit_width,
            "accepted_any_repeat": accepted_any,
            "attempts_last_accepted": attempts_last,
            "proof_bytes": proof_bytes,
        }
        if prove_times:
            entry["prove_seconds_median"] = statistics.median(prove_times)
            entry["prove_per_sec"] = 1.0 / statistics.median(prove_times) if statistics.median(prove_times) > 0 else None
            entry["verify_seconds_median"] = statistics.median(verify_times)
            entry["verify_per_sec"] = 1.0 / statistics.median(verify_times) if statistics.median(verify_times) > 0 else None
        else:
            entry["note"] = "no accepted sample within max_attempts across repeats"
        output.append(entry)

    print(json.dumps({
        "warning": "research-only synthetic benchmark; not a security or production result",
        "results": output,
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
