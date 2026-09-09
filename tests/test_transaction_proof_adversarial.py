"""Adversarial tests for the composed transaction proof.

The point of verify_transaction is that it is WITNESS-FREE: a dishonest
prover supplies only public data, so every attack below must be caught by
recomputation rather than trusted flags. Each test states the attack and
the expected rejection.
"""

import unittest
from dataclasses import replace
from decimal import Decimal

from pqct.balance_composition import SignedAmount
from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.hmc import bounded_ring_element
from pqct.matrix_generation import generate_hmc_key
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.protocol5 import Protocol5Parameters, protocol5_params_for_lambdas
from pqct.ring_commitment import ToyParameters
from pqct.transaction_proof import prove_transaction, verify_transaction


class TransactionAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.seed = b"tx-adv"
        self.k, self.m = 5, 1
        self.key = generate_hmc_key(self.seed + b"|key", self.params, self.m, self.k)
        self.distribution = Protocol1DistributionParameters(B=1, gaussian_tail=8, phi1=1, phi2=2)
        self.p1_params = RingProtocol1Parameters.from_paper_bounds(
            challenge_weight=4, challenge_coefficient_bound=2,
            B=1, p=2, k=self.k, m=self.m, d=8, phi1=2, phi2=8,
        )
        self.amounts = (SignedAmount(10, 1), SignedAmount(6, 1), SignedAmount(16, -1))
        self.signs = tuple(a.sign for a in self.amounts)
        self.p5 = protocol5_params_for_lambdas(
            self.signs, p=2, w=4, k=self.k, B=1, m=self.m, d=8,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )
        self.proof = prove_transaction(
            seed=self.seed, statement=b"tx-adv-statement", key=self.key,
            amounts=self.amounts, bit_width=self.k, distribution=self.distribution,
            p1_params=self.p1_params, p5=self.p5,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )

    def _verify(self, **overrides):
        args = dict(
            statement=b"tx-adv-statement", key=self.key,
            bit_commitments=self.proof.bit_commitments,
            binary_proofs=self.proof.binary_proofs,
            conservation=self.proof.conservation,
            signs=self.signs, bit_width=self.k,
            p1_params=self.p1_params, p5=self.p5,
        )
        args.update(overrides)
        return verify_transaction(**args)

    def test_honest_transaction_is_accepted(self):
        v = self._verify()
        self.assertTrue(v.dimensions_ok)
        self.assertTrue(v.signs_consistent)
        self.assertTrue(v.binary_ok)
        self.assertTrue(v.conservation_ok)
        self.assertTrue(v.accepted)
        self.assertEqual(v.binary_count, 3)
        self.assertTrue(all(v.conservation_gates))

    def test_tampered_protocol1_proof_is_rejected(self):
        """Replace one binary proof with another amount's proof: it must not
        verify against the commitment it did not prove."""
        proofs = list(self.proof.binary_proofs)
        proofs[1] = proofs[0]
        v = self._verify(binary_proofs=tuple(proofs))
        self.assertFalse(v.binary_ok)
        self.assertIn(1, v.binary_failures)
        self.assertFalse(v.accepted)

    def test_swapped_commitments_are_rejected(self):
        """Swap two public commitments; each proof now binds to the wrong one."""
        commits = list(self.proof.bit_commitments)
        commits[0], commits[1] = commits[1], commits[0]
        v = self._verify(bit_commitments=tuple(commits))
        self.assertFalse(v.binary_ok)
        self.assertFalse(v.accepted)

    def test_forged_flags_cannot_be_passed_in(self):
        """A malicious prover claiming accepted=True has no effect: the
        verifier recomputes everything from public data."""
        forged = replace(self.proof, shared_commitments_ok=True, binary_ok=True, conservation_ok=True)
        commits = list(forged.bit_commitments)
        commits[0], commits[1] = commits[1], commits[0]
        v = self._verify(bit_commitments=tuple(commits), binary_proofs=forged.binary_proofs)
        self.assertFalse(v.accepted)

    def test_sign_mismatch_is_rejected(self):
        """Flipping a sign breaks conservation; verifier must catch it."""
        bad_signs = (1, 1, 1)
        v = self._verify(signs=bad_signs)
        self.assertFalse(v.signs_consistent)
        self.assertFalse(v.accepted)

    def test_mismatched_commitment_set_breaks_shared_identity(self):
        """Conservation proof bound to DIFFERENT commitments than the binary
        proofs must be rejected -- the two halves must share one set."""
        unit = bounded_ring_element((1,) + (0,) * (self.params.n - 1), self.params)
        bogus_commits = tuple(
            tuple(value.add(unit) for value in row)
            for row in self.proof.bit_commitments
        )
        v = self._verify(bit_commitments=bogus_commits)
        self.assertFalse(v.conservation_ok)
        self.assertFalse(v.accepted)

    def test_dropped_proof_fails_dimensions(self):
        v = self._verify(binary_proofs=self.proof.binary_proofs[:2])
        self.assertFalse(v.dimensions_ok)
        self.assertFalse(v.accepted)

    def test_wrong_bit_width_rejected(self):
        v = self._verify(bit_width=self.k - 1)
        self.assertFalse(v.dimensions_ok)
        self.assertFalse(v.accepted)

    def test_truncated_commitment_row_rejected(self):
        commits = list(self.proof.bit_commitments)
        commits[0] = commits[0][:-1] if len(commits[0]) > 1 else ()
        v = self._verify(bit_commitments=tuple(commits))
        self.assertFalse(v.dimensions_ok)
        self.assertFalse(v.accepted)

    def test_empty_commitments_rejected(self):
        v = self._verify(bit_commitments=(), binary_proofs=(), signs=())
        self.assertFalse(v.dimensions_ok)
        self.assertFalse(v.accepted)


if __name__ == "__main__":
    unittest.main()
