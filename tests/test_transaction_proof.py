import unittest
from decimal import Decimal

from pqct.balance_composition import SignedAmount
from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.matrix_generation import generate_hmc_key
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.protocol5 import Protocol5Parameters
from pqct.ring_commitment import ToyParameters
from pqct.transaction_proof import TransactionProofError
from pqct.transaction_proof import prove_transaction


class TransactionProofTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.seed = b"tx-proof-seed"
        self.k, self.m = 5, 1
        self.key = generate_hmc_key(self.seed + b"|key", self.params, self.m, self.k)
        self.distribution = Protocol1DistributionParameters(
            B=1, gaussian_tail=8, phi1=1, phi2=2,
        )
        # Bounds with slack over the sampling sigmas (mirrors balance_transcript).
        self.p1_params = RingProtocol1Parameters.from_paper_bounds(
            challenge_weight=4, challenge_coefficient_bound=2,
            B=1, p=2, k=self.k, m=self.m, d=8,
            phi1=2, phi2=8,
        )
        self.p5 = Protocol5Parameters.from_research_bounds(
            p=2, w=4, k=self.k, B=1, m=self.m, d=8,
            phi2=Decimal("4"), phi3=Decimal("4"), sign_max=2,
        )

    def _prove(self, amounts, seed=None, statement=b"tx-statement"):
        return prove_transaction(
            seed=seed or self.seed, statement=statement, key=self.key,
            amounts=amounts, bit_width=self.k, distribution=self.distribution,
            p1_params=self.p1_params, p5=self.p5,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )

    def test_conserved_transaction_fully_accepted(self):
        amounts = (SignedAmount(10, 1), SignedAmount(6, 1), SignedAmount(16, -1))
        proof = self._prove(amounts)
        self.assertTrue(proof.shared_commitments_ok)
        self.assertTrue(proof.binary_ok)
        self.assertTrue(proof.conservation_ok)
        self.assertTrue(proof.accepted)
        self.assertEqual(len(proof.binary_proofs), 3)

    def test_shared_commitments_between_both_halves(self):
        amounts = (SignedAmount(7, 1), SignedAmount(7, -1))
        proof = self._prove(amounts, seed=b"shared-seed")
        # Protocol 5 must have committed to the SAME bits Protocol 1 proved.
        self.assertEqual(proof.conservation.bit_commitments, proof.bit_commitments)
        self.assertTrue(proof.shared_commitments_ok)

    def test_non_conserved_transaction_rejected(self):
        amounts = (SignedAmount(10, 1), SignedAmount(6, 1), SignedAmount(15, -1))
        with self.assertRaises(TransactionProofError) as caught:
            self._prove(amounts, seed=b"nonconserved-seed")
        self.assertIn("not conserved", str(caught.exception))

    def test_reproducible(self):
        amounts = (SignedAmount(3, 1), SignedAmount(5, 1), SignedAmount(8, -1))
        first = self._prove(amounts, seed=b"repro")
        second = self._prove(amounts, seed=b"repro")
        self.assertEqual(first.bit_commitments, second.bit_commitments)
        self.assertEqual(first.accepted, second.accepted)

    def test_empty_seed_rejected(self):
        with self.assertRaises(TransactionProofError):
            self._prove((SignedAmount(1, 1),), seed=b"")


if __name__ == "__main__":
    unittest.main()
