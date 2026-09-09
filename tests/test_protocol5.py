import unittest
from decimal import Decimal

from pqct.balance_composition import SignedAmount
from pqct.matrix_generation import generate_hmc_key
from pqct.protocol5 import Protocol5Error, Protocol5Parameters
from pqct.protocol5 import compute_sign_max, compute_t3
from pqct.protocol5 import derive_ring_cycle_mask
from pqct.protocol5 import prove_linear_equation, ring_cycle_mask_weighted_sum_is_zero
from pqct.protocol5 import verify_linear_equation
from pqct.ring_commitment import ToyParameters


class RingCycleMaskTests(unittest.TestCase):
    def setUp(self):
        from pqct.hmc import bounded_ring_element
        self.params = ToyParameters(n=8, q=17, k=1)
        self.r = lambda values: bounded_ring_element(values, self.params)

    def test_telescoping_mask_has_zero_weighted_sum(self):
        tail = (
            self.r((3, 1, -2, 0, 0, 0, 0, 0)),
            self.r((-1, 2, 0, 0, 0, 0, 0, 0)),
        )
        mask = derive_ring_cycle_mask(tail, self.params)
        self.assertEqual(len(mask), 3)
        self.assertTrue(ring_cycle_mask_weighted_sum_is_zero(mask))

    def test_empty_tail_rejected(self):
        with self.assertRaises(Protocol5Error):
            derive_ring_cycle_mask((), self.params)

    def test_sign_max(self):
        self.assertEqual(compute_sign_max((1, 1, -1)), 2)
        self.assertEqual(compute_sign_max((-1, -1, -1, 1)), 3)
        self.assertEqual(compute_t3((1, 1, -1), 2, 4, 5), Decimal(2 * 2) * Decimal(20).sqrt())


class Protocol5EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.seed = b"p5-e2e"
        self.k, self.m = 5, 1
        self.key = generate_hmc_key(self.seed + b"|key", self.params, self.m, self.k)
        self.p5 = Protocol5Parameters.from_research_bounds(
            p=2, w=4, k=self.k, B=1, m=self.m, d=8,
            phi2=Decimal("4"), phi3=Decimal("4"), sign_max=2,
        )

    def _prove(self, amounts, seed=b"p5-e2e", statement=b"e2e-statement", max_attempts=512):
        return prove_linear_equation(
            seed=seed, statement=statement, key=self.key,
            amounts=amounts, bit_width=self.k, p5=self.p5,
            phi2=Decimal("4"), phi3=Decimal("4"), max_attempts=max_attempts,
        )

    def test_conserved_transaction_proves_and_verifies(self):
        result = self._prove((SignedAmount(10, 1), SignedAmount(6, 1), SignedAmount(16, -1)))
        self.assertTrue(result.conserved)
        self.assertEqual(result.weighted_sum, 0)
        verification = verify_linear_equation(
            statement=b"e2e-statement", key_c=self.key,
            bit_commitments=result.bit_commitments, lambdas=result.lambdas,
            proof=result.proof, p5=self.p5, challenge_x=result.challenge_x,
        )
        self.assertTrue(verification.accepted)
        self.assertTrue(all((
            verification.f0_in_range, verification.f_norms_ok,
            verification.z_norm_ok, verification.commitment_equation_ok,
        )))

    def test_proof_is_reproducible(self):
        amounts = (SignedAmount(3, 1), SignedAmount(5, 1), SignedAmount(8, -1))
        first = self._prove(amounts, seed=b"repro-seed")
        second = self._prove(amounts, seed=b"repro-seed")
        self.assertEqual(first, second)

    def test_verifier_without_challenge_uses_fiat_shamir(self):
        result = self._prove((SignedAmount(7, 1), SignedAmount(7, -1)))
        verification = verify_linear_equation(
            statement=b"e2e-statement", key_c=self.key,
            bit_commitments=result.bit_commitments, lambdas=result.lambdas,
            proof=result.proof, p5=self.p5,
        )
        self.assertTrue(verification.accepted)
        self.assertEqual(verification.commitment_equation_ok, True)

    def test_tampered_response_tail_rejected(self):
        result = self._prove((SignedAmount(10, 1), SignedAmount(10, -1)))
        first = result.proof.response_tail[0]
        bumped_coeffs = tuple(
            (value + 1) % first.params.q for value in first.coeffs
        )
        tampered_first = type(first).from_coeffs(bumped_coeffs, first.params)
        tampered_tail = (tampered_first, *result.proof.response_tail[1:])
        from pqct.protocol5 import Protocol5Proof
        bad_proof = Protocol5Proof(
            result.proof.commitment_d, tampered_tail, result.proof.response_z,
        )
        verification = verify_linear_equation(
            statement=b"e2e-statement", key_c=self.key,
            bit_commitments=result.bit_commitments, lambdas=result.lambdas,
            proof=bad_proof, p5=self.p5, challenge_x=result.challenge_x,
        )
        self.assertFalse(verification.accepted)


class Protocol5CheatTests(unittest.TestCase):
    """The overflow-cheat discrimination at a small modulus where it bites."""

    def setUp(self):
        # q=17, k=5: +16 +16 -15 = 17 == 0 (mod 17) but != 0 over Z.
        # With q=12289 this cheat is unreachable (columns too small);
        # small q is deliberate so the f0 range gate is exercisable.
        self.params = ToyParameters(n=8, q=17, k=1)
        self.seed = b"p5-cheat"
        self.k, self.m = 5, 1
        self.key = generate_hmc_key(self.seed + b"|key", self.params, self.m, self.k)
        self.p5 = Protocol5Parameters.from_research_bounds(
            p=2, w=4, k=self.k, B=1, m=self.m, d=8,
            phi2=Decimal("4"), phi3=Decimal("4"), sign_max=2,
        )

    def test_mod_q_cheat_cannot_produce_accepted_proof(self):
        with self.assertRaises(Protocol5Error):
            prove_linear_equation(
                seed=self.seed, statement=b"cheat-statement", key=self.key,
                amounts=(
                    SignedAmount(16, 1), SignedAmount(16, 1), SignedAmount(15, -1),
                ),
                bit_width=self.k, p5=self.p5,
                phi2=Decimal("4"), phi3=Decimal("4"), max_attempts=8,
            )

    def test_cheat_columns_are_zero_mod_q_but_not_over_integers(self):
        from pqct.balance_composition import build_balance_columns
        cols = build_balance_columns(
            (SignedAmount(16, 1), SignedAmount(16, 1), SignedAmount(15, -1)), self.k,
        )
        self.assertEqual(cols.weighted_sum, self.params.q)
        self.assertFalse(cols.conserved)


if __name__ == "__main__":
    unittest.main()
