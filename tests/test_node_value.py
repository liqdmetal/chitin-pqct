"""Node tests for VALUE: authorized transfers and the attacks against them.

These run through the complete pipeline (envelope -> replay -> state ->
lattice proof -> authorization), which is the only place the interaction
between layers is tested. A proof-level or registry-level test alone cannot
catch a node that verifies proofs correctly but forgets to enforce ownership.
"""

import unittest
from decimal import Decimal

from pqct.authorization import (
    Note,
    NoteRegistry,
    authorization_message,
    generate_keypair,
    sign_authorization,
)
from pqct.balance_composition import SignedAmount
from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.experimental_node import ExperimentalNode
from pqct.matrix_generation import generate_hmc_key
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.protocol5 import protocol5_params_for_lambdas
from pqct.ring_commitment import ToyParameters
from pqct.transaction_proof import prove_transaction
from pqct.tx_envelope import TransactionEnvelope


class NodeValueTests(unittest.TestCase):
    def setUp(self):
        self.chain = b"chitin-testnet-0"
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.m, self.k = 1, 5
        self.key = generate_hmc_key(b"value|key", self.params, self.m, self.k)
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
        self.node = ExperimentalNode(chain_id=self.chain)
        self.alice = generate_keypair()
        self.bob = generate_keypair()
        # Fund alice from genesis.
        self.alice_note = Note(
            commitment=b"alice-16", owner=self.alice.public,
            created_by=b"genesis", index=0,
        )
        self.alice_id = self.node.registry.mint_genesis(self.alice_note)

    def _proof_for(self, envelope):
        statement = envelope.statement(
            bit_width=self.k, account_count=len(self.amounts)
        )
        proof = prove_transaction(
            seed=b"value-seed", statement=statement, key=self.key,
            amounts=self.amounts, bit_width=self.k,
            distribution=self.distribution, p1_params=self.p1, p5=self.p5,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )
        return statement, proof

    def _envelope(self, nonce):
        return TransactionEnvelope(
            chain_id=self.chain, prev_state_root=self.node.state_root,
            nonce=nonce, expiry_height=10_000,
        )

    def _submit(self, *, nonce=1, spent_ids=None, outputs=None, signer=None,
                sign_statement=None):
        envelope = self._envelope(nonce)
        statement, proof = self._proof_for(envelope)
        spent_ids = spent_ids if spent_ids is not None else [self.alice_id]
        outputs = outputs if outputs is not None else [
            Note(commitment=b"bob-16", owner=self.bob.public,
                 created_by=b"tx1", index=0)
        ]
        signer = signer or self.alice
        message = authorization_message(
            statement=sign_statement if sign_statement is not None else statement,
            spent_note_ids=spent_ids,
            created_note_ids=[n.note_id for n in outputs],
        )
        sigs = [sign_authorization(signer.secret, message) for _ in spent_ids]
        return self.node.submit(
            envelope=envelope, payload=b"payload", key=self.key,
            bit_commitments=proof.bit_commitments,
            binary_proofs=proof.binary_proofs,
            conservation=proof.conservation,
            signs=self.signs, bit_width=self.k,
            p1_params=self.p1, p5=self.p5,
            spent_note_ids=spent_ids, created_notes=outputs, signatures=sigs,
        )

    def test_authorized_transfer_is_accepted(self):
        ok, reason = self._submit(nonce=1)
        self.assertTrue(ok, reason)
        self.assertIn("authorized", reason)
        summary = self.node.summary()
        self.assertEqual(summary["spent_notes"], 1)
        self.assertEqual(summary["unspent_notes"], 1)

    def test_mint_from_nothing_is_rejected_at_the_node(self):
        """The attack that made 'value' impossible: fabricated inputs."""
        ok, reason = self._submit(nonce=2, spent_ids=[b"\xAA" * 32])
        self.assertFalse(ok)
        self.assertIn("unauthorized", reason)
        self.assertIn("does not exist", reason)

    def test_theft_is_rejected_at_the_node(self):
        ok, reason = self._submit(nonce=3, signer=self.bob)
        self.assertFalse(ok)
        self.assertIn("not authorized", reason)

    def test_double_spend_across_blocks_is_rejected(self):
        ok, _ = self._submit(nonce=1)
        self.assertTrue(ok)
        self.node.seal_block()
        second = [Note(commitment=b"bob-again", owner=self.bob.public,
                       created_by=b"tx2", index=0)]
        ok, reason = self._submit(nonce=2, outputs=second)
        self.assertFalse(ok)
        self.assertIn("already spent", reason)

    def test_signature_bound_to_the_wrong_statement_is_rejected(self):
        ok, reason = self._submit(nonce=4, sign_statement=b"other-statement")
        self.assertFalse(ok)
        self.assertIn("not authorized", reason)

    def test_rejected_spend_leaves_the_registry_untouched(self):
        before_unspent = dict(self.node.registry.unspent)
        before_spent = set(self.node.registry.spent)
        self._submit(nonce=5, signer=self.bob)
        self.assertEqual(self.node.registry.unspent, before_unspent)
        self.assertEqual(self.node.registry.spent, before_spent)

    def test_no_value_mode_is_labelled_and_does_not_move_notes(self):
        """Omitting note arguments must NEVER look like an authorized spend."""
        envelope = self._envelope(9)
        _, proof = self._proof_for(envelope)
        ok, reason = self.node.submit(
            envelope=envelope, payload=b"payload", key=self.key,
            bit_commitments=proof.bit_commitments,
            binary_proofs=proof.binary_proofs,
            conservation=proof.conservation,
            signs=self.signs, bit_width=self.k,
            p1_params=self.p1, p5=self.p5,
        )
        self.assertTrue(ok, reason)
        self.assertIn("NO-VALUE", reason)
        self.assertEqual(self.node.summary()["spent_notes"], 0)


if __name__ == "__main__":
    unittest.main()
