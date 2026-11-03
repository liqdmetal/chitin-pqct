"""Node tests for VALUE: authorized transfers and the attacks against them.

These run through the complete pipeline (envelope -> replay -> state ->
lattice proof -> authorization), which is the only place the interaction
between layers is tested. A proof-level or registry-level test alone cannot
catch a node that verifies proofs correctly but forgets to enforce ownership.
"""

import unittest
from dataclasses import replace
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
from pqct.public_transaction import (PublicTransaction, VerifierConfig, note_commitment,
                                     transaction_statement)
from pqct.protocol1_sampling import XofByteSource, sample_box_ring_vector
from pqct.relations import decompose_unsigned
from pqct.ring_commitment import RingElement


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
        self.config = VerifierConfig(self.key, self.p1, self.p5, self.signs, allow_proof_only=True)
        self.alice = generate_keypair()
        self.bob = generate_keypair()
        # Genesis notes commit to the EXACT inputs subsequently proved. Private
        # openings stay in this deterministic, valueless test fixture.
        self.genesis = []
        for index, amount in enumerate(self.amounts[:2]):
            opening = sample_box_ring_vector(XofByteSource(
                b"value-seed|rb|" + index.to_bytes(4, "big")), self.params, self.m, 1)
            bits = tuple(RingElement.from_coeffs((bit,) + (0,) * 7, self.params)
                         for bit in decompose_unsigned(amount.value, self.k))
            row = self.key.commit(bits, opening)
            self.genesis.append(Note(note_commitment(self.config, row),
                                     self.alice.public, b"genesis", index))
        self.node = ExperimentalNode(self.chain, self.config, tuple(self.genesis))
        self.alice_ids = tuple(note.note_id for note in self.genesis)

    def _proof_for(self, envelope):
        statement = transaction_statement(self.config, envelope)
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

    def _transaction(self, *, nonce=1, spent_ids=None, outputs=None, signer=None,
                     sign_statement=None, expiry=10_000):
        envelope = self._envelope(nonce)
        envelope = replace(envelope, expiry_height=expiry)
        statement, proof = self._proof_for(envelope)
        spent_ids = spent_ids if spent_ids is not None else self.alice_ids
        outputs = outputs if outputs is not None else [
            Note(note_commitment(self.config, proof.bit_commitments[2]),
                 self.bob.public, statement, 0)
        ]
        signer = signer or self.alice
        tx = PublicTransaction(self.config.profile_id, envelope, proof.public_proof(),
                               tuple(spent_ids), tuple(outputs))
        message = (sign_statement if sign_statement is not None
                   else tx.authorization_payload(self.config))
        sigs = [sign_authorization(signer.secret, message) for _ in spent_ids]
        return replace(tx, signatures=tuple(sigs))

    def _submit(self, **kwargs):
        return self.node.submit(self._transaction(**kwargs).encode(self.config))

    def test_authorized_transfer_is_accepted(self):
        ok, reason = self._submit(nonce=1)
        self.assertTrue(ok, reason)
        self.assertIn("authorized", reason)
        self.assertEqual(self.node.summary()["spent_notes"], 0)
        self.node.seal_block()
        summary = self.node.summary()
        self.assertEqual(summary["spent_notes"], 2)
        self.assertEqual(summary["unspent_notes"], 1)

    def test_mint_from_nothing_is_rejected_at_the_node(self):
        """The attack that made 'value' impossible: fabricated inputs."""
        ok, reason = self._submit(nonce=2, spent_ids=[b"\xAA" * 32, self.alice_ids[1]])
        self.assertFalse(ok)
        self.assertIn("does not exist", reason)

    def test_theft_is_rejected_at_the_node(self):
        ok, reason = self._submit(nonce=3, signer=self.bob)
        self.assertFalse(ok)
        self.assertIn("not authorized", reason)

    def test_double_spend_across_blocks_is_rejected(self):
        ok, _ = self._submit(nonce=1)
        self.assertTrue(ok)
        self.node.seal_block()
        ok, reason = self._submit(nonce=2)
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
        tx = PublicTransaction(self.config.profile_id, envelope, proof.public_proof(), proof_only=True)
        ok, reason = self.node.submit(tx.encode(self.config))
        self.assertTrue(ok, reason)
        self.assertIn("NO-VALUE", reason)
        self.assertEqual(self.node.summary()["spent_notes"], 0)

    def test_correct_signature_cannot_authorize_unproved_output(self):
        tx = self._transaction()
        wrong = replace(tx.created_notes[0], commitment=self.genesis[0].commitment)
        tx = replace(tx, created_notes=(wrong,), signatures=())
        signatures = tuple(sign_authorization(self.alice.secret, tx.authorization_payload(self.config))
                           for _ in tx.spent_note_ids)
        ok, reason = self.node.submit(replace(tx, signatures=signatures).encode(self.config))
        self.assertFalse(ok)
        self.assertIn("output note is not the commitment", reason)

    def test_existing_note_with_different_amount_cannot_be_proved_as_input(self):
        # A known, owned note can still be the WRONG commitment for this proof.
        tx = self._transaction(spent_ids=tuple(reversed(self.alice_ids)))
        ok, reason = self.node.submit(tx.encode(self.config))
        self.assertFalse(ok)
        self.assertIn("input note is not the commitment", reason)

    def test_read_only_validation_and_eviction_leave_committed_state_unchanged(self):
        payload = self._transaction().encode(self.config)
        before = dict(self.node.registry.unspent), set(self.node.guard.seen), self.node.state_root
        self.assertTrue(self.node.validate(payload)[0])
        self.assertEqual(self.node.mempool, [])
        self.assertTrue(self.node.submit(payload)[0])
        self.assertEqual((self.node.registry.unspent, self.node.guard.seen, self.node.state_root), before)
        self.node.evict(self.node.mempool[0].txid)
        self.assertTrue(self.node.submit(payload)[0])

    def test_failed_seal_has_no_partial_notes_replay_or_block_effects(self):
        self.assertTrue(self._submit()[0])
        envelope = replace(self._envelope(2), expiry_height=0)
        _, proof = self._proof_for(envelope)
        payload = PublicTransaction(self.config.profile_id, envelope, proof.public_proof(),
                                    proof_only=True).encode(self.config)
        self.assertTrue(self.node.submit(payload)[0])
        before = dict(self.node.registry.unspent), set(self.node.guard.seen), self.node.state_root
        with self.assertRaises(ValueError):
            self.node.seal_block()
        self.assertEqual((self.node.registry.unspent, self.node.guard.seen, self.node.state_root), before)
        self.assertEqual((self.node.height, len(self.node.blocks), len(self.node.mempool)), (0, 0, 2))

    def test_pending_double_spend_rejected_without_consuming_committed_notes(self):
        self.assertTrue(self._submit(nonce=1)[0])
        ok, reason = self._submit(nonce=2)
        self.assertFalse(ok)
        self.assertIn("already spent", reason)
        self.assertEqual(len(self.node.registry.unspent), 2)
        self.assertEqual(self.node.registry.spent, set())


if __name__ == "__main__":
    unittest.main()
