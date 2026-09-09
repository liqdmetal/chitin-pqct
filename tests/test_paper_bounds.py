import unittest
from decimal import Decimal

from pqct.paper_bounds import PaperBoundsError
from pqct.paper_bounds import completeness_error_protocol1
from pqct.paper_bounds import completeness_error_protocol5
from pqct.paper_bounds import gamma_bin, gamma_le
from pqct.paper_bounds import kappa_for_s, mu_phi
from pqct.paper_bounds import protocol1_q_precondition_holds
from pqct.paper_bounds import relation_rbin_bound, relation_rbin_prime_bound

# Gao's reported evaluation profile (pqct.parameters.GaoPaperProfile).
PAPER_Q = 2**49 - 2**18 + 2**9 + 1
PAPER_D = 64
PAPER_W = 56
PAPER_P = 8
PAPER_M = 60
PAPER_K = 64


class MuPhiTests(unittest.TestCase):
    def test_mu_matches_lemma6_definition(self):
        # mu(1) = exp(1/2 + 1/2) = e exactly.
        self.assertAlmostEqual(float(mu_phi(Decimal(1))), 2.718281828459045, places=12)
        # mu(2) = exp(1/4 + 1/8) = exp(0.375).
        self.assertAlmostEqual(float(mu_phi(Decimal(2))), 1.4549914146182013, places=12)

    def test_mu_decreases_as_phi_grows(self):
        self.assertGreater(mu_phi(Decimal(1)), mu_phi(Decimal(4)))
        self.assertGreater(mu_phi(Decimal(4)), mu_phi(Decimal(16)))

    def test_mu_rejects_nonpositive(self):
        with self.assertRaises(PaperBoundsError):
            mu_phi(Decimal(0))
        with self.assertRaises(PaperBoundsError):
            mu_phi(Decimal("-1"))

    def test_completeness_error_matches_formula(self):
        ce = completeness_error_protocol1(Decimal(1), Decimal(1))
        expected = Decimal(1) - Decimal(1) / (mu_phi(Decimal(1)) ** 2)
        self.assertEqual(ce, expected)
        self.assertLess(ce, 1)

    def test_protocol5_completeness_uses_three_mus(self):
        ce5 = completeness_error_protocol5(Decimal(1), Decimal(1), Decimal(1))
        expected = Decimal(1) - Decimal(1) / (mu_phi(Decimal(1)) ** 3)
        self.assertEqual(ce5, expected)
        # more stages => larger completeness error
        self.assertGreater(ce5, completeness_error_protocol1(Decimal(1), Decimal(1)))


class KappaTests(unittest.TestCase):
    def test_kappa_values(self):
        self.assertEqual(kappa_for_s(1), 0)
        self.assertEqual(kappa_for_s(2), 1)
        self.assertEqual(kappa_for_s(3), 3)

    def test_kappa_rejects_nonpositive(self):
        with self.assertRaises(PaperBoundsError):
            kappa_for_s(0)


class GammaBinTests(unittest.TestCase):
    def test_all_ones_matches_hand_computation(self):
        # 4*1^2*sqrt(1*1*(32*1*1*1*1 + 3*1*1*1)) = 4*sqrt(35)
        got = gamma_bin(1, 1, 1, 1, Decimal(1), Decimal(1), 1, 1)
        self.assertAlmostEqual(float(got), 4 * 35**0.5, places=12)

    def test_scales_with_p_squared(self):
        base = gamma_bin(1, 8, 4, 5, Decimal(2), Decimal(4), 1, 1)
        doubled = gamma_bin(2, 8, 4, 5, Decimal(2), Decimal(4), 1, 1)
        ratio = float(doubled) / float(base)
        # p appears as 4p^2 in front AND inside the first sqrt term
        # (32*d*p^2*k^3*phi1^4), but NOT in the second additive term
        # (3*phi2^2*B^2*m^2). So the ratio approaches 4*sqrt(4) = 8 from
        # below as the p-independent term becomes negligible -- it is not
        # exactly 8. Verified by hand: 4*sqrt(2048048/512048) = 7.99972.
        self.assertGreater(ratio, 7.99)
        self.assertLess(ratio, 8.0)

    def test_p_scaling_is_exact_when_second_term_vanishes(self):
        # Drive the p-independent term to negligible size (B*m tiny relative
        # to the p^2 term) and the ratio converges to exactly 8.
        base = gamma_bin(1, 8, 4, 5, Decimal(2), Decimal(4), 1, 1)
        doubled = gamma_bin(2, 8, 4, 5, Decimal(2), Decimal(4), 1, 1)
        big_k_base = gamma_bin(1, 8, 4, 500, Decimal(2), Decimal(4), 1, 1)
        big_k_doubled = gamma_bin(2, 8, 4, 500, Decimal(2), Decimal(4), 1, 1)
        self.assertAlmostEqual(
            float(big_k_doubled) / float(big_k_base), 8.0, places=6,
        )
        self.assertGreater(
            float(big_k_doubled) / float(big_k_base),
            float(doubled) / float(base),
        )

    def test_rejects_nonpositive_inputs(self):
        with self.assertRaises(PaperBoundsError):
            gamma_bin(0, 8, 4, 5, Decimal(2), Decimal(4), 1, 1)
        with self.assertRaises(PaperBoundsError):
            gamma_bin(1, 8, 4, 5, Decimal(0), Decimal(4), 1, 1)


class RelationBoundTests(unittest.TestCase):
    def test_rbin_all_ones(self):
        self.assertEqual(relation_rbin_bound(1, 1, 1), Decimal(1))

    def test_rbin_prime_all_ones_matches_8_sqrt3(self):
        got = relation_rbin_prime_bound(1, 1, 1, 1, Decimal(1), 1)
        self.assertAlmostEqual(float(got), 8 * 3**0.5, places=12)

    def test_rbin_prime_is_larger_than_rbin_for_typical_params(self):
        rbin = relation_rbin_bound(1, PAPER_M, PAPER_D)
        rbinp = relation_rbin_prime_bound(PAPER_M, PAPER_D, PAPER_W, PAPER_P, Decimal(11), 1)
        self.assertGreater(rbinp, rbin)


class GammaLeTests(unittest.TestCase):
    def test_all_ones_matches_4_sqrt3(self):
        # 4*1*1*1*1*1*1*sqrt(1^2 + 1 + 1) = 4*sqrt(3)
        got = gamma_le(Decimal(1), 1, 1, 1, 1, 1, 1, 1)
        self.assertAlmostEqual(float(got), 4 * 3**0.5, places=12)

    def test_grows_with_omega_l1_squared(self):
        small = gamma_le(Decimal(4), 1, 8, 1, 4, 2, 3, 3)
        large = gamma_le(Decimal(4), 1, 8, 1, 4, 2, 30, 3)
        self.assertGreater(large, small)

    def test_rejects_zero_omega(self):
        with self.assertRaises(PaperBoundsError):
            gamma_le(Decimal(4), 1, 8, 1, 4, 2, 0, 3)

    def test_rejects_s_below_one(self):
        with self.assertRaises(PaperBoundsError):
            gamma_le(Decimal(4), 1, 8, 1, 4, 2, 3, 0)


class QPreconditionTests(unittest.TestCase):
    """Theorem 1 requires q/2 > 16*(w*phi1)^2*p*k*d."""

    def test_TOY_FIXTURE_FAILS_THE_PRECONDITION(self):
        """HONEST RECORD: the toy fixture used across this test suite does NOT
        satisfy Theorem 1's precondition. q=12289 -> q/2 = 6144.5, but
        16*(4*1)^2*2*5*8 = 20480. The lab's soundness theorem therefore does
        not apply to these fixtures; they exercise algebra, not security.
        This test pins that fact so it can never be silently "fixed" away.
        """
        holds = protocol1_q_precondition_holds(
            q=12289, w=4, phi1=Decimal(1), p=2, k=5, d=8,
        )
        self.assertFalse(holds)

    def test_paper_profile_satisfies_precondition(self):
        # Gao's reported profile passes for plausible phi1 values.
        for phi1 in (Decimal(11), Decimal(100), Decimal(400)):
            self.assertTrue(protocol1_q_precondition_holds(
                q=PAPER_Q, w=PAPER_W, phi1=phi1, p=PAPER_P, k=PAPER_K, d=PAPER_D,
            ))

    def test_precondition_fails_when_phi1_too_large(self):
        # Even the paper q fails if phi1 is absurdly large.
        self.assertFalse(protocol1_q_precondition_holds(
            q=PAPER_Q, w=PAPER_W, phi1=Decimal(10**9), p=PAPER_P, k=PAPER_K, d=PAPER_D,
        ))

    def test_rejects_nonpositive_inputs(self):
        with self.assertRaises(PaperBoundsError):
            protocol1_q_precondition_holds(0, 4, Decimal(1), 2, 5, 8)
        with self.assertRaises(PaperBoundsError):
            protocol1_q_precondition_holds(12289, 4, Decimal(0), 2, 5, 8)


if __name__ == "__main__":
    unittest.main()
