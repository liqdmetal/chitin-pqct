import unittest
from decimal import Decimal

from pqct.goodness_of_fit import GoodnessOfFitError
from pqct.goodness_of_fit import chi_square_goodness_of_fit
from pqct.goodness_of_fit import chi_square_p_value
from pqct.gaussian import GaussianProfile


class ChiSquarePValueTests(unittest.TestCase):
    def test_matches_known_scipy_style_reference_values(self):
        # Reference values from scipy.stats.chi2.sf, independently
        # spot-checked (see docs/GOODNESS_OF_FIT.md for the full sweep).
        cases = [
            (3.84, 1, 0.05004352124870519),
            (5.99, 2, 0.05003662708658629),
            (10.0, 5, 0.07523524614651217),
            (20.0, 10, 0.029252688076961124),
        ]
        for statistic, df, expected in cases:
            got = chi_square_p_value(statistic, df)
            self.assertAlmostEqual(got, expected, places=6)

    def test_rejects_invalid_inputs(self):
        with self.assertRaises(GoodnessOfFitError):
            chi_square_p_value(-1.0, 5)
        with self.assertRaises(GoodnessOfFitError):
            chi_square_p_value(5.0, 0)

    def test_p_value_decreases_as_statistic_increases(self):
        p_small = chi_square_p_value(1.0, 5)
        p_large = chi_square_p_value(50.0, 5)
        self.assertGreater(p_small, p_large)


class ChiSquareGoodnessOfFitTests(unittest.TestCase):
    def test_uniform_die_fits_uniform_law(self):
        observed = {1: 18, 2: 16, 3: 15, 4: 17, 5: 16, 6: 18}
        expected = {v: Decimal(1) / Decimal(6) for v in range(1, 7)}
        result = chi_square_goodness_of_fit(observed, expected, min_expected=1.0)
        self.assertGreater(result.p_value, 0.05)
        self.assertEqual(result.total_samples, 100)

    def test_skewed_die_rejects_uniform_law(self):
        observed = {1: 5, 2: 5, 3: 5, 4: 5, 5: 5, 6: 475}
        expected = {v: Decimal(1) / Decimal(6) for v in range(1, 7)}
        result = chi_square_goodness_of_fit(observed, expected, min_expected=1.0)
        self.assertLess(result.p_value, 0.001)

    def test_gaussian_profile_own_samples_fit_its_own_law(self):
        """A GaussianProfile's own inverse-CDF samples must fit its own PMF.

        This is a self-consistency floor: if the SAMPLER disagreed with its
        OWN normalized weights, that would be a bug in gaussian.py, not a
        research question. It does not test whether the finite profile
        matches Gao's exact infinite D_sigma law (see docs/GOODNESS_OF_FIT.md).
        """
        from pqct.gaussian import empirical_histogram
        profile = GaussianProfile(Decimal("2.5"), 8)
        histogram = empirical_histogram(profile, b"gof-self-check", 4000)
        weights = profile.weights
        total_weight = profile.total_weight
        expected = {
            value: weight / total_weight
            for value, weight in zip(profile.support, weights)
        }
        result = chi_square_goodness_of_fit(histogram, expected, min_expected=5.0)
        self.assertGreater(result.p_value, 0.01)

    def test_missing_support_value_rejected(self):
        observed = {1: 10, 2: 10, 99: 5}
        expected = {1: Decimal("0.5"), 2: Decimal("0.5")}
        with self.assertRaises(GoodnessOfFitError):
            chi_square_goodness_of_fit(observed, expected)

    def test_probabilities_must_sum_to_one(self):
        observed = {1: 10, 2: 10}
        expected = {1: Decimal("0.4"), 2: Decimal("0.4")}
        with self.assertRaises(GoodnessOfFitError):
            chi_square_goodness_of_fit(observed, expected)

    def test_too_few_bins_after_merging_rejected(self):
        observed = {1: 100}
        expected = {1: Decimal("1")}
        with self.assertRaises(GoodnessOfFitError):
            chi_square_goodness_of_fit(observed, expected, min_expected=5.0)


if __name__ == "__main__":
    unittest.main()
