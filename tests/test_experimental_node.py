"""Node-level tests: the attacks that only exist once transactions do.

Proof-level tests cannot reach these: replaying a valid proof, submitting it
to the wrong chain, building on a stale state root, or reusing a nonce after a
block seals. Each is a real way a network dies.
"""

import unittest
from decimal import Decimal

from pqct.balance_composition import SignedAmount
from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.experimental_node import (
    ExperimentalNode,
    NodeError,
    genesis_state_root,
    next_state_root,
)
from pqct.matrix_generation import generate_hmc_key
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.protocol5 import protocol5_params_for_lambdas
from pqct.ring_commitment import ToyParameters
from pqct.transaction_proof import prove_transaction
from pqct.tx_envelope import TransactionEnvelope
from pqct.public_transaction import PublicTransaction, VerifierConfig, transaction_statement


class NodeTestBase(unittest.TestCase):
    def setUp(self):
        self.chain = b"chitin-testnet-0"
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.m, self.k = 1, 5
        self.key = generate_hmc_key(b"node|key", self.params, self.m, self.k)
        self.distribution = Protocol1DistributionParameters(
            B=1, gaussian_tail=8, phi1=1, phi2=2
        )
        self.p1 = RingProtocol1Parameters.from_paper_bounds(
            challenge_weight=4, challenge_coefficient_bound=2,
            B=1, p=2, k=self.k, m=self.m, d=8, phi1=2, phi2=8,
        )
        self.amounts = (SignedAmount(10, 1), SignedAmount(6, 1), SignedAmount(16, -1))
        self.signs = tuple(a.sign for a in self.amounts)
        self.p5 = protocol5_params_for_lambdas(
            self.signs, p=2, w=4, k=self.k, B=1, m=self.m, d=8,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )
        self.config = VerifierConfig(self.key, self.p1, self.p5, self.signs, allow_proof_only=True)
        self.node = ExperimentalNode(chain_id=self.chain, verifier=self.config)

    def build_tx(self, *, nonce, state_root=None, chain_id=None, expiry=1000,
                 seed=b"node-seed"):
        envelope = TransactionEnvelope(
            chain_id=chain_id or self.chain,
            prev_state_root=state_root if state_root is not None else self.node.state_root,
            nonce=nonce,
            expiry_height=expiry,
        )
        statement = transaction_statement(self.config, envelope)
        proof = prove_transaction(
            seed=seed, statement=statement, key=self.key,
            amounts=self.amounts, bit_width=self.k,
            distribution=self.distribution, p1_params=self.p1, p5=self.p5,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )
        return envelope, proof

    def payload(self, envelope, proof):
        return PublicTransaction(self.config.profile_id, envelope,
                                 proof.public_proof(), proof_only=True).encode(self.config)

    def submit(self, envelope, proof):
        return self.node.submit(self.payload(envelope, proof))


class NodeAcceptanceTests(NodeTestBase):
    def test_genesis_root_is_chain_specific(self):
        self.assertNotEqual(
            genesis_state_root(b"chain-a"), genesis_state_root(b"chain-b")
        )
        self.assertEqual(
            genesis_state_root(self.chain), genesis_state_root(self.chain)
        )

    def test_rejects_empty_chain_id(self):
        with self.assertRaises(NodeError):
            ExperimentalNode(chain_id=b"", verifier=self.config)

    def test_honest_transaction_is_accepted(self):
        envelope, proof = self.build_tx(nonce=1)
        ok, reason = self.submit(envelope, proof)
        self.assertTrue(ok, reason)
        self.assertEqual(len(self.node.mempool), 1)
        self.assertTrue(all(self.node.mempool[0].conservation_gates))

    def test_block_seals_and_advances_state(self):
        envelope, proof = self.build_tx(nonce=1)
        self.assertTrue(self.submit(envelope, proof)[0])
        before = self.node.state_root
        block = self.node.seal_block()
        self.assertEqual(block.height, 1)
        self.assertEqual(block.prev_state_root, before)
        self.assertNotEqual(block.state_root, before)
        self.assertEqual(self.node.height, 1)
        self.assertEqual(len(block.txids), 1)
        self.assertEqual(self.node.mempool, [])

    def test_state_root_depends_on_txids(self):
        root = self.node.state_root
        self.assertNotEqual(
            next_state_root(root, (b"a" * 32,)),
            next_state_root(root, (b"b" * 32,)),
        )
        # order matters
        self.assertNotEqual(
            next_state_root(root, (b"a" * 32, b"b" * 32)),
            next_state_root(root, (b"b" * 32, b"a" * 32)),
        )


class NodeAttackTests(NodeTestBase):
    def test_exact_replay_is_rejected(self):
        envelope, proof = self.build_tx(nonce=1)
        self.assertTrue(self.submit(envelope, proof)[0])
        ok, reason = self.submit(envelope, proof)
        self.assertFalse(ok)
        self.assertIn("replay", reason)

    def test_replay_after_block_still_rejected(self):
        """Sealing a block must not clear replay protection."""
        envelope, proof = self.build_tx(nonce=1)
        self.assertTrue(self.submit(envelope, proof)[0])
        self.node.seal_block()
        ok, reason = self.submit(envelope, proof)
        self.assertFalse(ok)
        self.assertIn("replay", reason)

    def test_wrong_chain_is_rejected(self):
        envelope, proof = self.build_tx(nonce=2, chain_id=b"chitin-testnet-1")
        ok, reason = self.submit(envelope, proof)
        self.assertFalse(ok)
        self.assertIn("wrong chain", reason)

    def test_stale_state_root_is_rejected(self):
        """A tx built on an old state root must not apply to a newer chain."""
        first, proof1 = self.build_tx(nonce=1)
        self.assertTrue(self.submit(first, proof1)[0])
        stale_root = self.node.state_root
        self.node.seal_block()  # chain advances; stale_root is now old
        envelope, proof = self.build_tx(nonce=2, state_root=stale_root)
        ok, reason = self.submit(envelope, proof)
        self.assertFalse(ok)
        self.assertIn("stale state", reason)

    def test_expired_transaction_is_rejected(self):
        envelope, proof = self.build_tx(nonce=1, expiry=0)
        for _ in range(2):
            self.node.seal_block()
        ok, reason = self.submit(envelope, proof)
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_foreign_proof_cannot_be_reused_under_fresh_nonce(self):
        """Take a VALID proof for nonce=1 and resubmit it inside an envelope
        claiming nonce=2. The nonce is bound into the statement, so the node's
        derived statement no longer matches and the proof must fail."""
        _, proof = self.build_tx(nonce=1)
        forged = TransactionEnvelope(
            chain_id=self.chain,
            prev_state_root=self.node.state_root,
            nonce=2,
            expiry_height=1000,
        )
        ok, reason = self.submit(forged, proof)
        self.assertFalse(ok)
        self.assertIn("proof rejected", reason)

    def test_node_never_trusts_a_submitted_statement(self):
        """There is no API to pass a statement in -- the node derives it.
        This test documents that as an interface guarantee."""
        import inspect
        sig = inspect.signature(ExperimentalNode.submit)
        self.assertNotIn("statement", sig.parameters)

    def test_rejections_are_recorded(self):
        envelope, proof = self.build_tx(nonce=1, chain_id=b"other")
        self.submit(envelope, proof)
        self.assertEqual(len(self.node.rejections), 1)

    def test_summary_reports_experimental_status(self):
        summary = self.node.summary()
        self.assertIn("EXPERIMENTAL", summary["status"])
        self.assertIn("valueless", summary["status"])


if __name__ == "__main__":
    unittest.main()
