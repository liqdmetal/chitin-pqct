import unittest
from decimal import Decimal

from pqct.gaussian import GaussianError, GaussianProfile, empirical_histogram, sample_truncated, shake_source


class GaussianTests(unittest.TestCase):
    def test_profile_is_normalized_and_tail_is_reported(self):
        profile = GaussianProfile(Decimal("2.5"), 12)
        self.assertGreater(profile.total_weight, Decimal(0))
        self.assertLess(profile.omitted_two_sided_tail_bound, Decimal("0.00001"))
        source = shake_source(b"gaussian-vector-v1")
        draws = [sample_truncated(profile, source) for _ in range(100)]
        self.assertTrue(all(value in profile.support for value in draws))

    def test_histogram_is_reproducible(self):
        profile = GaussianProfile(Decimal("1.5"), 8)
        self.assertEqual(empirical_histogram(profile, b"seed", 100), empirical_histogram(profile, b"seed", 100))
        self.assertNotEqual(empirical_histogram(profile, b"seed", 100), empirical_histogram(profile, b"other", 100))

    def test_invalid_profile_rejected(self):
        with self.assertRaises(GaussianError):
            GaussianProfile(Decimal(0), 2)
        with self.assertRaises(GaussianError):
            GaussianProfile(Decimal("1.0"), -1)


if __name__ == "__main__":
    unittest.main()
