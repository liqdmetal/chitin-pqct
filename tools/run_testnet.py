"""Run the Chitin experimental testnet: real proofs, real blocks, real attacks.

    python tools/run_testnet.py

EXPERIMENTAL, VALUELESS, NOT CONSENSUS. Single process, in-memory, no p2p, no
mining, toy ring parameters. Its job is to exercise the crypto under
transaction-shaped pressure and to SHOW the attack rejections, not to be a
blockchain.

The scenario below mines three blocks of honest transactions and then runs six
attacks against the live node, printing what each gate says.
"""

from __future__ import annotations

import sys
import time
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pqct.balance_composition import SignedAmount
from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.experimental_node import ExperimentalNode
from pqct.matrix_generation import generate_hmc_key
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.protocol5 import protocol5_params_for_lambdas
from pqct.ring_commitment import ToyParameters
from pqct.transaction_proof import prove_transaction
from pqct.tx_envelope import TransactionEnvelope
from pqct.wire_codec import encode_matrix, encode_params

CHAIN_ID = b"chitin-testnet-0"
BIT_WIDTH = 5


def banner(text: str) -> None:
    print()
    print("=" * 72)
    print(text)
    print("=" * 72)


class Wallet:
    """Builds envelope-bound transactions against a node's current state."""

    def __init__(self, node: ExperimentalNode):
        self.node = node
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.m = 1
        self.key = generate_hmc_key(b"testnet|key", self.params, self.m, BIT_WIDTH)
        self.distribution = Protocol1DistributionParameters(
            B=1, gaussian_tail=8, phi1=1, phi2=2
        )
        self.p1 = RingProtocol1Parameters.from_paper_bounds(
            challenge_weight=4, challenge_coefficient_bound=2,
            B=1, p=2, k=BIT_WIDTH, m=self.m, d=8, phi1=2, phi2=8,
        )

    def build(self, amounts, nonce, *, chain_id=None, state_root=None,
              expiry=10_000, seed=None):
        signs = tuple(a.sign for a in amounts)
        p5 = protocol5_params_for_lambdas(
            signs, p=2, w=4, k=BIT_WIDTH, B=1, m=self.m, d=8,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )
        envelope = TransactionEnvelope(
            chain_id=chain_id or CHAIN_ID,
            prev_state_root=(
                state_root if state_root is not None else self.node.state_root
            ),
            nonce=nonce,
            expiry_height=expiry,
        )
        statement = envelope.statement(
            bit_width=BIT_WIDTH, account_count=len(amounts)
        )
        started = time.perf_counter()
        proof = prove_transaction(
            seed=seed or f"tx-{nonce}".encode(), statement=statement,
            key=self.key, amounts=amounts, bit_width=BIT_WIDTH,
            distribution=self.distribution, p1_params=self.p1, p5=p5,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )
        elapsed = time.perf_counter() - started
        payload = (
            encode_params(self.params)
            + envelope.encode()
            + encode_matrix(proof.bit_commitments)
        )
        return envelope, proof, p5, signs, payload, elapsed

    def send(self, node, amounts, nonce, **kwargs):
        envelope, proof, p5, signs, payload, elapsed = self.build(
            amounts, nonce, **kwargs
        )
        started = time.perf_counter()
        ok, reason = node.submit(
            envelope=envelope, payload=payload, key=self.key,
            bit_commitments=proof.bit_commitments,
            binary_proofs=proof.binary_proofs,
            conservation=proof.conservation,
            signs=signs, bit_width=BIT_WIDTH,
            p1_params=self.p1, p5=p5,
        )
        verify_time = time.perf_counter() - started
        return ok, reason, elapsed, verify_time, len(payload), (envelope, proof, p5, signs, payload)


def main() -> int:
    banner("CHITIN EXPERIMENTAL TESTNET  --  valueless, unproven crypto")
    node = ExperimentalNode(chain_id=CHAIN_ID)
    wallet = Wallet(node)
    print(f"chain_id     : {CHAIN_ID.decode()}")
    print(f"genesis root : {node.state_root.hex()}")

    scenarios = [
        ("in 10 + 6, out 16", (SignedAmount(10, 1), SignedAmount(6, 1), SignedAmount(16, -1))),
        ("in 7 + 9, out 16", (SignedAmount(7, 1), SignedAmount(9, 1), SignedAmount(16, -1))),
        ("in 20 + 11, out 31", (SignedAmount(20, 1), SignedAmount(11, 1), SignedAmount(31, -1))),
    ]

    banner("PHASE 1: honest transactions, one block each")
    nonce = 1
    keep = None
    for label, amounts in scenarios:
        ok, reason, prove_s, verify_s, size, artifacts = wallet.send(
            node, amounts, nonce
        )
        total = sum(a.value * a.sign for a in amounts)
        print(f"\n  tx#{nonce}  {label}")
        print(f"    integer sum      : {total}  (must be 0)")
        print(f"    accepted         : {ok}  -- {reason}")
        print(f"    prove / verify   : {prove_s*1000:.0f} ms / {verify_s*1000:.0f} ms")
        print(f"    payload on wire  : {size} bytes")
        if keep is None:
            keep = artifacts
        block = node.seal_block()
        print(f"    sealed block #{block.height}, state -> {block.state_root.hex()[:24]}...")
        nonce += 1

    banner("PHASE 2: attacks against the live node")
    old_envelope, old_proof, old_p5, old_signs, old_payload = keep

    def attack(name, envelope, proof, p5, signs, payload):
        ok, reason = node.submit(
            envelope=envelope, payload=payload, key=wallet.key,
            bit_commitments=proof.bit_commitments,
            binary_proofs=proof.binary_proofs,
            conservation=proof.conservation,
            signs=signs, bit_width=BIT_WIDTH,
            p1_params=p5 and wallet.p1, p5=p5,
        )
        verdict = "!!! ACCEPTED (BAD) !!!" if ok else "rejected"
        print(f"\n  [{name}]\n    -> {verdict}: {reason}")
        return ok

    bad = 0
    # 1. exact replay of a previously mined transaction
    bad += attack("replay a mined tx verbatim", old_envelope, old_proof,
                  old_p5, old_signs, old_payload)

    # 2. same proof, fresh nonce (nonce is bound into the statement)
    forged_nonce = TransactionEnvelope(
        CHAIN_ID, node.state_root, 9001, 10_000)
    bad += attack("reuse proof under a fresh nonce", forged_nonce, old_proof,
                  old_p5, old_signs, old_payload)

    # 3. wrong chain
    _, p_other, p5_other, s_other, pay_other, _ = wallet.build(
        scenarios[0][1], 4242, chain_id=b"chitin-testnet-1")
    env_other = TransactionEnvelope(
        b"chitin-testnet-1", node.state_root, 4242, 10_000)
    bad += attack("submit a testnet-1 tx to testnet-0", env_other, p_other,
                  p5_other, s_other, pay_other)

    # 4. stale state root (built on genesis after 3 blocks)
    from pqct.experimental_node import genesis_state_root
    _, p_stale, p5_stale, s_stale, pay_stale, _ = wallet.build(
        scenarios[0][1], 5150, state_root=genesis_state_root(CHAIN_ID))
    env_stale = TransactionEnvelope(
        CHAIN_ID, genesis_state_root(CHAIN_ID), 5150, 10_000)
    bad += attack("build on a stale (genesis) state root", env_stale, p_stale,
                  p5_stale, s_stale, pay_stale)

    # 5. expired
    _, p_exp, p5_exp, s_exp, pay_exp, _ = wallet.build(
        scenarios[0][1], 6161, expiry=0)
    env_exp = TransactionEnvelope(CHAIN_ID, node.state_root, 6161, 0)
    bad += attack("expired transaction (expiry 0)", env_exp, p_exp,
                  p5_exp, s_exp, pay_exp)

    # 6. non-conserving amounts: the PROVER must refuse to build it at all
    print("\n  [non-conserving amounts 16 + 16 - 15]")
    try:
        wallet.build(
            (SignedAmount(16, 1), SignedAmount(16, 1), SignedAmount(15, -1)), 7777
        )
        print("    -> !!! PROVER BUILT IT (BAD) !!!")
        bad += 1
    except Exception as error:
        print(f"    -> rejected by prover: {type(error).__name__}: "
              f"{str(error)[:70]}")

    banner("RESULT")
    summary = node.summary()
    for key, value in summary.items():
        print(f"  {key:12s}: {value}")
    print(f"\n  attacks that succeeded: {bad}  (must be 0)")
    print(f"  attacks rejected      : {len(node.rejections)} recorded at node")

    if bad:
        print("\n  FAILURE: an attack was accepted.")
        return 1
    print("\n  All honest transactions mined; all attacks rejected.")
    print("  Reminder: this exercises the plumbing. The underlying proofs are")
    print("  UNPROVEN research crypto -- see docs/HARD_BLOCKER_PROGRESS.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
