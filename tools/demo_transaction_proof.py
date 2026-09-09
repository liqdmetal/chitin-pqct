"""CLI demo: composed transaction proof (Protocol 1 + Protocol 5).

Synthetic research demo only. Runs three scenarios and prints verdicts:
  1. honest conserved transaction   -> accepted
  2. non-conserved transaction      -> rejected (fail-fast + no P5 proof)
  3. mod-q cheat (small q)          -> rejected (f_0 overflow gate)

No testnet, no real balances, no keys. Toy parameters.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decimal import Decimal

from pqct.balance_composition import SignedAmount
from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.matrix_generation import generate_hmc_key
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.protocol5 import Protocol5Error, Protocol5Parameters
from pqct.ring_commitment import ToyParameters
from pqct.transaction_proof import TransactionProofError, prove_transaction


def _fixture(q: int, k: int, m: int, seed: bytes):
    params = ToyParameters(n=8, q=q, k=1)
    key = generate_hmc_key(seed + b"|key", params, m, k)
    distribution = Protocol1DistributionParameters(B=1, gaussian_tail=8, phi1=1, phi2=2)
    p1_params = RingProtocol1Parameters.from_paper_bounds(
        challenge_weight=4, challenge_coefficient_bound=2,
        B=1, p=2, k=k, m=m, d=8, phi1=2, phi2=8,
    )
    p5 = Protocol5Parameters.from_research_bounds(
        p=2, w=4, k=k, B=1, m=m, d=8,
        phi2=Decimal("4"), phi3=Decimal("4"), sign_max=2,
    )
    return key, distribution, p1_params, p5


def scenario_honest() -> dict:
    key, dist, p1, p5 = _fixture(12289, 5, 1, b"demo-honest")
    amounts = (SignedAmount(10, 1), SignedAmount(6, 1), SignedAmount(16, -1))
    try:
        proof = prove_transaction(
            seed=b"demo-honest", statement=b"demo-tx", key=key,
            amounts=amounts, bit_width=5, distribution=dist,
            p1_params=p1, p5=p5, phi2=Decimal("4"), phi3=Decimal("4"),
        )
    except (TransactionProofError, Protocol5Error) as error:
        return {"scenario": "honest", "verdict": "UNEXPECTED FAILURE", "error": str(error)}
    return {
        "scenario": "honest conserved (+10 +6 -16 = 0 over Z)",
        "accepted": proof.accepted,
        "shared_commitments_ok": proof.shared_commitments_ok,
        "binary_ok": proof.binary_ok,
        "conservation_ok": proof.conservation_ok,
        "binary_proofs": len(proof.binary_proofs),
        "p5_attempts": proof.conservation.attempts,
        "verdict": "ACCEPTED" if proof.accepted else "REJECTED",
    }


def scenario_non_conserved() -> dict:
    key, dist, p1, p5 = _fixture(12289, 5, 1, b"demo-nonconserved")
    amounts = (SignedAmount(10, 1), SignedAmount(6, 1), SignedAmount(15, -1))
    try:
        prove_transaction(
            seed=b"demo-nonconserved", statement=b"demo-tx", key=key,
            amounts=amounts, bit_width=5, distribution=dist,
            p1_params=p1, p5=p5, phi2=Decimal("4"), phi3=Decimal("4"),
        )
        return {"scenario": "non-conserved", "verdict": "UNEXPECTED ACCEPT"}
    except TransactionProofError as error:
        return {
            "scenario": "non-conserved (+10 +6 -15 = 1 != 0)",
            "verdict": "REJECTED",
            "reason": str(error),
        }


def scenario_modq_cheat() -> dict:
    # q=17, k=5: +16 +16 -15 = 17 == 0 (mod 17) but 17 != 0 over Z.
    key, dist, p1, p5 = _fixture(17, 5, 1, b"demo-cheat")
    amounts = (SignedAmount(16, 1), SignedAmount(16, 1), SignedAmount(15, -1))
    try:
        prove_transaction(
            seed=b"demo-cheat", statement=b"demo-tx", key=key,
            amounts=amounts, bit_width=5, distribution=dist,
            p1_params=p1, p5=p5, phi2=Decimal("4"), phi3=Decimal("4"),
            p5_max_attempts=8,
        )
        return {"scenario": "mod-q cheat", "verdict": "UNEXPECTED ACCEPT"}
    except TransactionProofError as error:
        return {
            "scenario": "mod-q cheat (+16 +16 -15 = 17 = q; 0 mod q, 17 over Z)",
            "verdict": "REJECTED",
            "reason": str(error),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Composed transaction proof demo")
    parser.add_argument("--json", action="store_true", help="emit raw JSON")
    args = parser.parse_args()
    results = [scenario_honest(), scenario_non_conserved(), scenario_modq_cheat()]
    if args.json:
        print(json.dumps({
            "warning": "synthetic research demo; toy parameters; not a testnet",
            "results": results,
        }, indent=2, default=str))
        return
    print("=" * 68)
    print(" PQ-CT TRANSACTION PROOF DEMO  (synthetic research, toy params)")
    print(" Protocol 1 binary proofs + Protocol 5 conservation, shared commits")
    print("=" * 68)
    for entry in results:
        print(f"\n[{entry['verdict']}] {entry['scenario']}")
        for key, value in entry.items():
            if key in ("scenario", "verdict"):
                continue
            print(f"    {key}: {value}")
    print("\n" + "=" * 68)
    print(" Boundary: research only. No testnet, mainnet, real balances,")
    print(" or security claim. See docs/TESTNET_SCOPE.md.")
    print("=" * 68)


if __name__ == "__main__":
    main()
