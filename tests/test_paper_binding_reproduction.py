import sys
import os
import unittest
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.reproduce_paper_binding import (
    PHI1, PHI2, B, D, W, P, N_MOD, M, K, S, Q, DELTA,
    b_amor, b_bin, eq2_rhs, gamma_bin_reduced, gamma_bin_theorem1, kappa,
)


class PaperBindingReproductionTests(unittest.TestCase):
    """Pin our transcription of Gao Eq.(21)/(2) to the paper's OWN printed
    numbers (Section 8, S=2: 2*gamma_bin ~ 2.86e14 < min{q,...} ~ 4.10e14).

    Reproducing a published numeric claim is a much stronger check on a
    hand-transcribed formula than any self-consistency test: if a constant,
    exponent or factor were wrong, these values would miss.
    """

    def test_reproduces_paper_2_gamma_bin(self):
        got = float(2 * gamma_bin_reduced(S))
        target = 2.86e14
        self.assertAlmostEqual(got / target, 1.0, delta=0.01)

    def test_reproduces_paper_eq2_rhs(self):
        got = float(eq2_rhs(S))
        target = 4.10e14
        self.assertAlmostEqual(got / target, 1.0, delta=0.02)

    def test_paper_claims_bamor_below_bbin_for_s_le_2(self):
        self.assertLess(b_amor(1), b_bin(1))
        self.assertLess(b_amor(2), b_bin(2))

    def test_gamma_bin_is_below_q_so_instance_is_well_posed(self):
        """The corrected reading: with the paper's REDUCED Eq.(21) bound and
        its actual phi_1=phi_2=15, gamma_bin < q, so Eq.(2) can hold and the
        SIS instance is NOT trivially easy."""
        self.assertLess(gamma_bin_reduced(S), Decimal(Q))
        self.assertLess(2 * gamma_bin_reduced(S), eq2_rhs(S))

    def test_unreduced_theorem1_bound_is_larger_than_reduced(self):
        """Eq.(21) exists precisely to shrink the bound; verify it does."""
        self.assertGreater(gamma_bin_theorem1(S), gamma_bin_reduced(S))

    def test_kappa_matches_paper(self):
        self.assertEqual(kappa(1), 0)
        self.assertEqual(kappa(2), 1)
        self.assertEqual(kappa(3), 3)

    def test_evaluation_params_are_the_papers(self):
        """Guards against silently drifting away from the published profile."""
        self.assertEqual(PHI1, Decimal(15))
        self.assertEqual(PHI2, Decimal(15))
        self.assertEqual((int(D), int(W), int(P)), (64, 56, 8))
        self.assertEqual((int(N_MOD), int(M)), (29, 60))
        self.assertEqual(Q, 2**49 - 2**18 + 2**9 + 1)
        self.assertEqual(DELTA, Decimal("1.0045"))


if __name__ == "__main__":
    unittest.main()
