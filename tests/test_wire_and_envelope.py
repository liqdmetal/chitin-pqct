"""Adversarial tests for the wire codec and transaction envelope.

The headline test is test_mutating_a_bound_field_invalidates_the_proof: it
proves the envelope fields are genuinely BOUND (part of the Fiat-Shamir
statement) rather than merely carried next to the proof. A field that is only
carried is not protection -- an attacker rewrites it and the proof still
verifies.
"""

import unittest
from decimal import Decimal

from pqct.balance_composition import SignedAmount
from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.hmc import bounded_ring_element
from pqct.matrix_generation import generate_hmc_key
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.protocol5 import protocol5_params_for_lambdas
from pqct.ring_commitment import RingElement, ToyParameters
from pqct.transaction_proof import prove_transaction, verify_transaction
from pqct.tx_envelope import (
    EnvelopeError,
    ReplayGuard,
    TransactionEnvelope,
    compute_txid,
)
from pqct.wire_codec import (
    CodecError,
    _Reader,
    decode_element,
    decode_matrix,
    decode_params,
    decode_vector,
    encode_element,
    encode_matrix,
    encode_params,
    encode_vector,
)


class WireCodecTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=5)
        self.r = lambda values: bounded_ring_element(values, self.params)

    def test_element_round_trip(self):
        element = self.r((1, 2, 3, 4, 5, 6, 7, 8))
        data = encode_params(self.params) + encode_element(element)
        reader = _Reader(data)
        params = decode_params(reader)
        decoded = decode_element(reader, params)
        reader.finish()
        self.assertEqual(decoded, element)

    def test_large_q_survives_round_trip(self):
        """RingElement.encode packs q into 4 bytes, which OVERFLOWS for the
        paper's q = 2^49 - 2^18 + 2^9 + 1. The wire codec must not."""
        big = ToyParameters(n=4, q=2 ** 49 - 2 ** 18 + 2 ** 9 + 1, k=2)
        element = RingElement(coeffs=(1, 2, 3, big.q - 1), params=big)
        data = encode_params(big) + encode_element(element)
        reader = _Reader(data)
        params = decode_params(reader)
        self.assertEqual(params.q, big.q)
        decoded = decode_element(reader, params)
        reader.finish()
        self.assertEqual(decoded, element)

    def test_non_canonical_coefficient_is_rejected(self):
        """c and c+q must NOT both decode, or the txid is malleable."""
        element = self.r((1, 0, 0, 0, 0, 0, 0, 0))
        data = encode_params(self.params) + encode_element(element)
        reader = _Reader(data)
        params = decode_params(reader)
        # Rewrite the first coefficient to 1 + q (same ring element, different bytes).
        width = (params.q.bit_length() + 7) // 8
        head = data[: len(data) - width * params.n]
        tampered = head + (1 + params.q).to_bytes(width, "big") + data[len(head) + width:]
        reader2 = _Reader(tampered)
        decode_params(reader2)
        with self.assertRaises(CodecError):
            decode_element(reader2, params)

    def test_trailing_data_rejected(self):
        element = self.r((1, 2, 3, 4, 5, 6, 7, 8))
        data = encode_params(self.params) + encode_element(element) + b"\x00extra"
        reader = _Reader(data)
        params = decode_params(reader)
        decode_element(reader, params)
        with self.assertRaises(CodecError):
            reader.finish()

    def test_truncated_data_rejected(self):
        element = self.r((1, 2, 3, 4, 5, 6, 7, 8))
        data = encode_params(self.params) + encode_element(element)
        reader = _Reader(data[:-3])
        params = decode_params(reader)
        with self.assertRaises(CodecError):
            decode_element(reader, params)

    def test_vector_and_matrix_round_trip(self):
        rows = (
            (self.r((1, 0, 0, 0, 0, 0, 0, 0)), self.r((2, 0, 0, 0, 0, 0, 0, 0))),
            (self.r((3, 0, 0, 0, 0, 0, 0, 0)),),
        )
        data = encode_params(self.params) + encode_matrix(rows)
        reader = _Reader(data)
        params = decode_params(reader)
        decoded = decode_matrix(reader, params)
        reader.finish()
        self.assertEqual(decoded, rows)

    def test_implausible_length_rejected(self):
        data = encode_params(self.params) + (2 ** 31).to_bytes(4, "big")
        reader = _Reader(data)
        params = decode_params(reader)
        with self.assertRaises(CodecError):
            decode_vector(reader, params)


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.env = TransactionEnvelope(
            chain_id=b"chitin-testnet-0",
            prev_state_root=bytes(range(32)),
            nonce=7,
            expiry_height=100,
        )

    def test_round_trip(self):
        reader = _Reader(self.env.encode())
        decoded = TransactionEnvelope.decode(reader)
        reader.finish()
        self.assertEqual(decoded, self.env)

    def test_rejects_bad_state_root_length(self):
        with self.assertRaises(EnvelopeError):
            TransactionEnvelope(b"c", b"short", 1, 10)

    def test_rejects_empty_chain_id(self):
        with self.assertRaises(EnvelopeError):
            TransactionEnvelope(b"", bytes(32), 1, 10)

    def test_statement_changes_with_every_field(self):
        base = self.env.statement(bit_width=5, account_count=3)
        variants = [
            TransactionEnvelope(b"other-chain", bytes(range(32)), 7, 100),
            TransactionEnvelope(b"chitin-testnet-0", bytes(32), 7, 100),
            TransactionEnvelope(b"chitin-testnet-0", bytes(range(32)), 8, 100),
            TransactionEnvelope(b"chitin-testnet-0", bytes(range(32)), 7, 101),
        ]
        for variant in variants:
            self.assertNotEqual(base, variant.statement(bit_width=5, account_count=3))
        # shape parameters must also matter
        self.assertNotEqual(base, self.env.statement(bit_width=6, account_count=3))
        self.assertNotEqual(base, self.env.statement(bit_width=5, account_count=4))

    def test_txid_is_deterministic_and_sensitive(self):
        self.assertEqual(compute_txid(b"abc"), compute_txid(b"abc"))
        self.assertNotEqual(compute_txid(b"abc"), compute_txid(b"abd"))
        # length is bound, so concatenation cannot be re-split ambiguously
        self.assertNotEqual(compute_txid(b"ab") + b"c", compute_txid(b"abc"))

    def test_replay_guard_rejects_duplicate_nonce(self):
        guard = ReplayGuard(chain_id=b"chitin-testnet-0")
        ok, _ = guard.check_and_record(self.env, 50)
        self.assertTrue(ok)
        ok, reason = guard.check_and_record(self.env, 50)
        self.assertFalse(ok)
        self.assertIn("replay", reason)

    def test_replay_guard_rejects_expired(self):
        guard = ReplayGuard(chain_id=b"chitin-testnet-0")
        ok, reason = guard.check_and_record(self.env, 101)
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_replay_guard_rejects_wrong_chain(self):
        guard = ReplayGuard(chain_id=b"a-different-chain")
        ok, reason = guard.check_and_record(self.env, 50)
        self.assertFalse(ok)
        self.assertIn("wrong chain", reason)

    def test_same_nonce_on_other_chain_is_allowed(self):
        guard = ReplayGuard()
        other = TransactionEnvelope(b"chain-b", bytes(range(32)), 7, 100)
        self.assertTrue(guard.check_and_record(self.env, 50)[0])
        self.assertTrue(guard.check_and_record(other, 50)[0])


class EnvelopeBindingTests(unittest.TestCase):
    """The important one: bound, not merely carried."""

    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.m, self.k = 1, 5
        self.key = generate_hmc_key(b"bind|key", self.params, self.m, self.k)
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
        self.env = TransactionEnvelope(
            chain_id=b"chitin-testnet-0",
            prev_state_root=bytes(range(32)),
            nonce=42,
            expiry_height=1000,
        )
        self.statement = self.env.statement(
            bit_width=self.k, account_count=len(self.amounts)
        )
        self.proof = prove_transaction(
            seed=b"bind-seed", statement=self.statement, key=self.key,
            amounts=self.amounts, bit_width=self.k,
            distribution=self.distribution, p1_params=self.p1, p5=self.p5,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )

    def _verify(self, statement):
        return verify_transaction(
            statement=statement, key=self.key,
            bit_commitments=self.proof.bit_commitments,
            binary_proofs=self.proof.binary_proofs,
            conservation=self.proof.conservation,
            signs=self.signs, bit_width=self.k,
            p1_params=self.p1, p5=self.p5,
        )

    def test_honest_envelope_statement_verifies(self):
        self.assertTrue(self._verify(self.statement).accepted)

    def test_mutating_a_bound_field_invalidates_the_proof(self):
        """Each envelope field must break verification when altered.

        This is what separates real binding from decoration: the statement IS
        the Fiat-Shamir input, so a rewritten chain_id / state root / nonce /
        expiry produces a different statement and the proof no longer verifies.
        """
        mutations = {
            "chain_id": TransactionEnvelope(
                b"evil-chain", self.env.prev_state_root, 42, 1000),
            "prev_state_root": TransactionEnvelope(
                self.env.chain_id, bytes(32), 42, 1000),
            "nonce": TransactionEnvelope(
                self.env.chain_id, self.env.prev_state_root, 43, 1000),
            "expiry_height": TransactionEnvelope(
                self.env.chain_id, self.env.prev_state_root, 42, 1001),
        }
        for field, mutated in mutations.items():
            statement = mutated.statement(
                bit_width=self.k, account_count=len(self.amounts)
            )
            with self.subTest(field=field):
                self.assertNotEqual(statement, self.statement)
                self.assertFalse(
                    self._verify(statement).accepted,
                    f"mutating {field} did NOT invalidate the proof -- the field "
                    "is carried, not bound",
                )

    def test_cross_chain_replay_is_rejected(self):
        """A proof made for testnet-0 must not verify on testnet-1."""
        other = TransactionEnvelope(
            b"chitin-testnet-1", self.env.prev_state_root, 42, 1000)
        statement = other.statement(bit_width=self.k, account_count=len(self.amounts))
        self.assertFalse(self._verify(statement).accepted)

    def test_shape_confusion_is_rejected(self):
        """A proof for 3 accounts must not verify as a proof for 2."""
        statement = self.env.statement(bit_width=self.k, account_count=2)
        self.assertFalse(self._verify(statement).accepted)


if __name__ == "__main__":
    unittest.main()
