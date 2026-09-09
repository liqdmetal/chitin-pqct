import unittest
from decimal import Decimal

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.check_completeness_error import predicted_acceptance, wilson_interval
from pqct.paper_bounds import mu_phi


class PredictedAcceptanceTests(unittest.TestCase):
    def test_matches_paper_formula(self):
        # Lemma 6: acceptance prob = 1/(mu(phi1)*mu(phi2))
        phi1, phi2 = Decimal("2"), Decimal("3")
        got = predicted_acceptance(phi1, phi2)
        expected = Decimal(1) / (mu_phi(phi1) * mu_phi(phi2))
        self.assertEqual(got, expected)

    def test_in_unit_interval(self):
        for phi in (Decimal("1"), Decimal("4"), Decimal("16")):
            p = predicted_acceptance(phi, phi)
            self.assertGreater(p, 0)
            self.assertLessEqual(p, 1)

    def test_acceptance_increases_with_phi(self):
        # wider mask (larger phi) -> higher acceptance (fewer rejects)
        low = predicted_acceptance(Decimal("1"), Decimal("1"))
        high = predicted_acceptance(Decimal("8"), Decimal("8"))
        self.assertGreater(high, low)

    def test_mu_of_one_is_e(self):
        self.assertAlmostEqual(float(mu_phi(Decimal(1))), 2.718281828, places=8)


class WilsonIntervalTests(unittest.TestCase):
    def test_covers_point_estimate(self):
        lo, hi = wilson_interval(50, 100)
        self.assertLessEqual(lo, Decimal("0.5"))
        self.assertGreaterEqual(hi, Decimal("0.5"))

    def test_narrows_with_more_trials(self):
        lo_small, hi_small = wilson_interval(5, 10)
        lo_big, hi_big = wilson_interval(500, 1000)
        self.assertGreater(hi_small - lo_small, hi_big - lo_big)

    def test_bounds_within_unit_interval(self):
        lo, hi = wilson_interval(0, 100)
        self.assertGreaterEqual(lo, Decimal(0))
        self.assertLessEqual(hi, Decimal(1))

    def test_all_accept_gives_high_bound(self):
        lo, hi = wilson_interval(100, 100)
        self.assertEqual(hi, Decimal(1))
        self.assertGreater(lo, Decimal("0.9"))

    def test_rejects_zero_trials(self):
        with self.assertRaises(ValueError):
            wilson_interval(0, 0)


if __name__ == "__main__":
    unittest.main()
