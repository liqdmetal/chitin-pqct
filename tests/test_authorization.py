"""Adversarial tests for ownership, provenance, and double-spend.

The headline test is test_mint_from_nothing_is_now_rejected: before this
layer existed, a transaction with fabricated inputs passed every check
because 1,000,000 - 1,000,000 = 0 conserves. That is the attack that makes
"value" impossible, and it must now fail.
"""

import unittest

from pqcrypto import ml_dsa_65

from pqct.authorization import (
    PUBLIC_KEY_SIZE,
    SIGNATURE_SIZE,
    AuthorizationError,
    Keypair,
    Note,
    NoteRegistry,
    address_for,
    authorization_message,
    generate_keypair,
    sign_authorization,
    verify_signature,
)


class SignaturePrimitiveTests(unittest.TestCase):
    def setUp(self):
        self.kp = generate_keypair()

    def test_sign_and_verify_round_trip(self):
        sig = sign_authorization(self.kp.secret, b"hello")
        self.assertTrue(verify_signature(self.kp.public, b"hello", sig))

    def test_verify_returns_a_real_bool_not_none(self):
        """pqcrypto.verify returns None on success, which is FALSY. Our
        wrapper must return True, or every `if verify(...)` inverts."""
        sig = sign_authorization(self.kp.secret, b"hello")
        result = verify_signature(self.kp.public, b"hello", sig)
        self.assertIsInstance(result, bool)
        self.assertIs(result, True)
        # and the raw library really does return None -- documents the trap
        self.assertIsNone(
            ml_dsa_65.verify(self.kp.public, b"CHITIN-AUTH-V1" + b"hello", sig)
        )

    def test_tampered_message_fails(self):
        sig = sign_authorization(self.kp.secret, b"hello")
        self.assertFalse(verify_signature(self.kp.public, b"hello!", sig))

    def test_wrong_key_fails(self):
        other = generate_keypair()
        sig = sign_authorization(self.kp.secret, b"hello")
        self.assertFalse(verify_signature(other.public, b"hello", sig))

    def test_tampered_signature_fails(self):
        sig = bytearray(sign_authorization(self.kp.secret, b"hello"))
        sig[0] ^= 0xFF
        self.assertFalse(verify_signature(self.kp.public, b"hello", bytes(sig)))

    def test_malformed_sizes_fail_closed(self):
        sig = sign_authorization(self.kp.secret, b"hello")
        self.assertFalse(verify_signature(b"short", b"hello", sig))
        self.assertFalse(verify_signature(self.kp.public, b"hello", b"short"))

    def test_rejects_malformed_keypair(self):
        with self.assertRaises(AuthorizationError):
            Keypair(public=b"short", secret=self.kp.secret)
        with self.assertRaises(AuthorizationError):
            Keypair(public=self.kp.public, secret=b"short")

    def test_address_is_deterministic_and_distinct(self):
        self.assertEqual(self.kp.address, address_for(self.kp.public))
        self.assertEqual(len(self.kp.address), 20)
        self.assertNotEqual(self.kp.address, generate_keypair().address)


class NoteTests(unittest.TestCase):
    def setUp(self):
        self.alice = generate_keypair()

    def _note(self, commitment=b"c1", index=0, owner=None):
        return Note(
            commitment=commitment,
            owner=owner or self.alice.public,
            created_by=b"tx0",
            index=index,
        )

    def test_note_id_binds_every_field(self):
        base = self._note().note_id
        self.assertNotEqual(base, self._note(commitment=b"c2").note_id)
        self.assertNotEqual(base, self._note(index=1).note_id)
        self.assertNotEqual(
            base, self._note(owner=generate_keypair().public).note_id
        )
        self.assertNotEqual(
            base,
            Note(commitment=b"c1", owner=self.alice.public,
                 created_by=b"tx1", index=0).note_id,
        )

    def test_rejects_malformed_notes(self):
        with self.assertRaises(AuthorizationError):
            Note(commitment=b"", owner=self.alice.public, created_by=b"t", index=0)
        with self.assertRaises(AuthorizationError):
            Note(commitment=b"c", owner=b"short", created_by=b"t", index=0)
        with self.assertRaises(AuthorizationError):
            Note(commitment=b"c", owner=self.alice.public, created_by=b"t", index=-1)

    def test_authorization_message_binds_inputs_and_outputs(self):
        base = authorization_message(
            statement=b"s", spent_note_ids=[b"a" * 32], created_note_ids=[b"b" * 32]
        )
        self.assertNotEqual(base, authorization_message(
            statement=b"s2", spent_note_ids=[b"a" * 32], created_note_ids=[b"b" * 32]))
        self.assertNotEqual(base, authorization_message(
            statement=b"s", spent_note_ids=[b"c" * 32], created_note_ids=[b"b" * 32]))
        self.assertNotEqual(base, authorization_message(
            statement=b"s", spent_note_ids=[b"a" * 32], created_note_ids=[b"d" * 32]))

    def test_message_resists_regrouping(self):
        """Length prefixes must stop (x,y),() from colliding with (x),(y)."""
        self.assertNotEqual(
            authorization_message(
                statement=b"s", spent_note_ids=[b"x" * 32, b"y" * 32],
                created_note_ids=[]),
            authorization_message(
                statement=b"s", spent_note_ids=[b"x" * 32],
                created_note_ids=[b"y" * 32]),
        )


class SpendAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.alice = generate_keypair()
        self.bob = generate_keypair()
        self.registry = NoteRegistry()
        self.funded = Note(
            commitment=b"alice-100", owner=self.alice.public,
            created_by=b"genesis", index=0,
        )
        self.funded_id = self.registry.mint_genesis(self.funded)
        self.statement = b"statement-bytes"

    def _spend(self, *, spent_ids=None, outputs=None, signer=None,
               statement=None):
        spent_ids = spent_ids if spent_ids is not None else [self.funded_id]
        outputs = outputs if outputs is not None else [
            Note(commitment=b"bob-100", owner=self.bob.public,
                 created_by=b"tx1", index=0)
        ]
        statement = statement if statement is not None else self.statement
        message = authorization_message(
            statement=statement,
            spent_note_ids=spent_ids,
            created_note_ids=[n.note_id for n in outputs],
        )
        signer = signer or self.alice
        sigs = [sign_authorization(signer.secret, message) for _ in spent_ids]
        return spent_ids, outputs, sigs, statement

    def test_owner_can_spend(self):
        spent, outputs, sigs, statement = self._spend()
        ok, reason = self.registry.authorize_spend(
            statement=statement, spent_note_ids=spent,
            created_notes=outputs, signatures=sigs)
        self.assertTrue(ok, reason)
        self.registry.apply_spend(spent_note_ids=spent, created_notes=outputs)
        self.assertEqual(self.registry.summary()["unspent_notes"], 1)
        self.assertEqual(self.registry.summary()["spent_notes"], 1)

    def test_mint_from_nothing_is_now_rejected(self):
        """THE headline attack. Fabricated inputs conserve arithmetically
        (1,000,000 - 1,000,000 = 0) but have no provenance."""
        fake_id = b"\xAA" * 32
        spent, outputs, sigs, statement = self._spend(spent_ids=[fake_id])
        ok, reason = self.registry.authorize_spend(
            statement=statement, spent_note_ids=spent,
            created_notes=outputs, signatures=sigs)
        self.assertFalse(ok)
        self.assertIn("does not exist", reason)

    def test_thief_cannot_spend_someone_elses_note(self):
        spent, outputs, sigs, statement = self._spend(signer=self.bob)
        ok, reason = self.registry.authorize_spend(
            statement=statement, spent_note_ids=spent,
            created_notes=outputs, signatures=sigs)
        self.assertFalse(ok)
        self.assertIn("not authorized", reason)

    def test_double_spend_is_rejected(self):
        spent, outputs, sigs, statement = self._spend()
        self.assertTrue(self.registry.authorize_spend(
            statement=statement, spent_note_ids=spent,
            created_notes=outputs, signatures=sigs)[0])
        self.registry.apply_spend(spent_note_ids=spent, created_notes=outputs)

        second = [Note(commitment=b"bob-again", owner=self.bob.public,
                       created_by=b"tx2", index=0)]
        message = authorization_message(
            statement=statement, spent_note_ids=spent,
            created_note_ids=[n.note_id for n in second])
        sigs2 = [sign_authorization(self.alice.secret, message)]
        ok, reason = self.registry.authorize_spend(
            statement=statement, spent_note_ids=spent,
            created_notes=second, signatures=sigs2)
        self.assertFalse(ok)
        self.assertIn("already spent", reason)

    def test_signature_for_different_statement_is_rejected(self):
        """Replay across chain/state/nonce: the statement is in the message."""
        spent, outputs, sigs, _ = self._spend(statement=b"other-statement")
        ok, reason = self.registry.authorize_spend(
            statement=self.statement, spent_note_ids=spent,
            created_notes=outputs, signatures=sigs)
        self.assertFalse(ok)
        self.assertIn("not authorized", reason)

    def test_output_swap_after_signing_is_rejected(self):
        """Outputs are signed, so re-targeting them invalidates the auth."""
        spent, outputs, sigs, statement = self._spend()
        attacker_output = [Note(commitment=b"bob-100", owner=generate_keypair().public,
                                created_by=b"tx1", index=0)]
        ok, reason = self.registry.authorize_spend(
            statement=statement, spent_note_ids=spent,
            created_notes=attacker_output, signatures=sigs)
        self.assertFalse(ok)
        self.assertIn("not authorized", reason)

    def test_no_inputs_is_rejected(self):
        ok, reason = self.registry.authorize_spend(
            statement=self.statement, spent_note_ids=[],
            created_notes=[], signatures=[])
        self.assertFalse(ok)
        self.assertIn("no inputs", reason)

    def test_signature_count_mismatch_is_rejected(self):
        spent, outputs, _, statement = self._spend()
        ok, reason = self.registry.authorize_spend(
            statement=statement, spent_note_ids=spent,
            created_notes=outputs, signatures=[])
        self.assertFalse(ok)
        self.assertIn("signature count", reason)

    def test_duplicate_input_in_one_tx_is_rejected(self):
        """Spending the same note twice inside one transaction."""
        spent, outputs, sigs, statement = self._spend(
            spent_ids=[self.funded_id, self.funded_id])
        ok, reason = self.registry.authorize_spend(
            statement=statement, spent_note_ids=spent,
            created_notes=outputs, signatures=sigs)
        self.assertFalse(ok)
        self.assertIn("duplicate input", reason)

    def test_duplicate_output_in_one_tx_is_rejected(self):
        clash = Note(commitment=b"same", owner=self.bob.public,
                     created_by=b"tx1", index=0)
        spent, outputs, sigs, statement = self._spend(outputs=[clash, clash])
        ok, reason = self.registry.authorize_spend(
            statement=statement, spent_note_ids=spent,
            created_notes=outputs, signatures=sigs)
        self.assertFalse(ok)
        self.assertIn("duplicate output", reason)

    def test_recreating_an_existing_note_is_rejected(self):
        spent, _, _, statement = self._spend()
        outputs = [self.funded]  # already in the registry
        message = authorization_message(
            statement=statement, spent_note_ids=spent,
            created_note_ids=[n.note_id for n in outputs])
        sigs = [sign_authorization(self.alice.secret, message)]
        ok, reason = self.registry.authorize_spend(
            statement=statement, spent_note_ids=spent,
            created_notes=outputs, signatures=sigs)
        self.assertFalse(ok)
        self.assertIn("already exists", reason)

    def test_failed_authorization_does_not_mutate_state(self):
        """Verification must be side-effect free, or a rejected tx corrupts
        the registry."""
        before_unspent = dict(self.registry.unspent)
        before_spent = set(self.registry.spent)
        spent, outputs, sigs, statement = self._spend(signer=self.bob)
        self.registry.authorize_spend(
            statement=statement, spent_note_ids=spent,
            created_notes=outputs, signatures=sigs)
        self.assertEqual(self.registry.unspent, before_unspent)
        self.assertEqual(self.registry.spent, before_spent)

    def test_genesis_cannot_be_minted_twice(self):
        with self.assertRaises(AuthorizationError):
            self.registry.mint_genesis(self.funded)


if __name__ == "__main__":
    unittest.main()
