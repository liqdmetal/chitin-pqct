"""Regression tests for the audited transaction acceptance boundaries."""

import unittest
from dataclasses import fields, is_dataclass, replace

from tests.test_experimental_node import NodeTestBase
from pqct.matrix_generation import generate_hmc_key
from pqct.ring_commitment import ToyParameters
from pqct.public_transaction import (PublicTransaction, decode_transaction, MAGIC,
                                     MAX_TRANSACTION_BYTES)
from pqct.wire_codec import CodecError, _Reader, decode_params, encode_params
from pqct.tx_envelope import compute_txid


class BoundaryRegressions(NodeTestBase):
    def test_invalid_submission_does_not_burn_valid_nonce(self):
        valid, proof = self.build_tx(nonce=7)
        stale, _ = self.build_tx(nonce=7, state_root=b"x" * 32)
        self.assertFalse(self.submit(stale, proof)[0])
        accepted, reason = self.submit(valid, proof)
        self.assertTrue(accepted, reason)

    def test_distinct_verified_transactions_have_distinct_ids(self):
        first, proof1 = self.build_tx(nonce=1)
        second, proof2 = self.build_tx(nonce=2)
        self.assertTrue(self.submit(first, proof1)[0])
        self.assertTrue(self.submit(second, proof2)[0])
        self.assertNotEqual(self.node.mempool[0].txid, self.node.mempool[1].txid)

    def test_full_public_codec_round_trip_excludes_private_witnesses(self):
        envelope, private = self.build_tx(nonce=1)
        payload = self.payload(envelope, private)
        tx = decode_transaction(payload, self.config)
        self.assertEqual(tx.encode(self.config), payload)
        self.assertTrue(self.node.validate(payload)[0])
        forbidden = {"masks", "amounts", "columns", "attempts", "rejection", "weighted_sum"}
        def walk(value):
            if is_dataclass(value):
                self.assertFalse(forbidden.intersection(f.name for f in fields(value)))
                for f in fields(value):
                    walk(getattr(value, f.name))
            elif isinstance(value, tuple):
                for item in value:
                    walk(item)
        walk(tx)
        unsafe = replace(tx, proof=private)
        with self.assertRaises(CodecError):
            unsafe.encode(self.config)
        unsafe = replace(tx, proof=replace(tx.proof, binary_proofs=private.binary_proofs))
        with self.assertRaises(CodecError):
            unsafe.encode(self.config)

    def test_serialized_proof_mutation_changes_txid_and_fails_verification(self):
        envelope, private = self.build_tx(nonce=1)
        payload = self.payload(envelope, private)
        tx = decode_transaction(payload, self.config)
        binary = tx.proof.binary_proofs[0]
        response = binary.responses_g[0]
        changed = response[0].add(response[0].__class__.from_coeffs((1,) + (0,) * 7, self.params))
        bad_binary = replace(binary, responses_g=((changed,) + response[1:],))
        bad_proof = replace(tx.proof, binary_proofs=(bad_binary,) + tx.proof.binary_proofs[1:])
        bad_payload = replace(tx, proof=bad_proof).encode(self.config)
        self.assertNotEqual(compute_txid(payload), compute_txid(bad_payload))
        self.assertFalse(self.node.submit(bad_payload)[0])
        self.assertTrue(self.node.submit(payload)[0])

    def test_malformed_bytes_fail_closed_without_allocating_from_declared_counts(self):
        envelope, private = self.build_tx(nonce=1)
        payload = self.payload(envelope, private)
        cases = [b"", payload[:-1], payload + b"trailing", b"x" * (MAX_TRANSACTION_BYTES + 1)]
        for cut in (len(MAGIC), len(MAGIC) + 31, len(payload) // 2):
            cases.append(payload[:cut])
        # First public commitment vector has an explicit count. Inflate it;
        # decoder must reject the count before constructing its coefficients.
        offset = len(MAGIC) + 32 + len(envelope.encode()) + 5 + len(self.signs)
        cases.append(payload[:offset] + b"\xff" * 4 + payload[offset + 4:])
        for hostile in cases:
            with self.subTest(size=len(hostile)):
                self.assertFalse(self.node.submit(hostile)[0])
                self.assertEqual(self.node.guard.seen, set())
        self.assertTrue(self.node.submit(payload)[0])

    def test_foreign_bounds_profile_cannot_override_node_policy(self):
        envelope, private = self.build_tx(nonce=1)
        payload = self.payload(envelope, private)
        relaxed = replace(self.config, p1=replace(self.p1, g_bound=self.p1.g_bound * 100))
        tx = decode_transaction(payload, self.config)
        foreign = replace(tx, profile_id=relaxed.profile_id).encode(relaxed)
        ok, reason = self.node.submit(foreign)
        self.assertFalse(ok)
        self.assertIn("profile", reason)

    def test_strict_profile_does_not_accept_proof_only_mode(self):
        envelope, private = self.build_tx(nonce=1)
        strict = replace(self.config, allow_proof_only=False)
        tx = PublicTransaction(strict.profile_id, envelope, private.public_proof(), proof_only=True)
        with self.assertRaises(CodecError):
            tx.encode(strict)

    def test_node_accepts_only_complete_bytes(self):
        import inspect
        self.assertEqual(tuple(inspect.signature(self.node.submit).parameters), ("payload",))


class WideModulusRegression(unittest.TestCase):
    def test_transcript_serialization_supports_wide_modulus(self):
        params = ToyParameters(n=8, q=2**49 + 1, k=1)
        key = generate_hmc_key(b"wide-q", params, 1, 5)
        self.assertTrue(key.encode())
        self.assertTrue(key.G_r[0][0].encode())

    def test_wide_modulus_fiat_shamir_transcript_can_be_derived(self):
        from pqct.binary_protocol1_ring import _derive_zeta, RingProtocol1Parameters
        params = ToyParameters(n=8, q=2**49 + 1, k=1)
        key = generate_hmc_key(b"wide-q", params, 1, 5)
        bounds = RingProtocol1Parameters(4, 2, 100, 100, 100)
        challenge = _derive_zeta(b"statement", key, key, key, key,
                                (key.G_r[0],), bounds)
        self.assertEqual(challenge.params, params)

    def test_noncanonical_and_oversized_parameter_encodings_are_rejected(self):
        params = ToyParameters(n=8, q=12289, k=1)
        raw = encode_params(params)
        noncanonical = raw[:4] + bytes((raw[4] + 1, 0)) + raw[5:]
        for malformed in (noncanonical, raw[:4] + b"\xff" + b"\x01" * 255 + raw[-4:]):
            with self.assertRaises(CodecError):
                decode_params(_Reader(malformed))
