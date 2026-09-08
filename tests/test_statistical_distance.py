import unittest
from decimal import Decimal

from pqct.statistical_distance import (
    StatisticalDistanceError,
    conditioned_tv_upper_bound,
    finite_normalizer,
    gaussian_product_tv_upper_bound,
    inverse_cdf_grid_tv_upper_bound,
    omitted_unnormalized_mass_upper_bound,
    product_tv_union_bound,
    truncation_tv_upper_bound,
)


class StatisticalDistanceTests(unittest.TestCase):
    def test_truncation_bound_is_positive_and_below_one(self):
        sigma = Decimal("2.5")
        bound = truncation_tv_upper_bound(sigma, 12)
        self.assertGreater(bound, 0)
        self.assertLess(bound, 1)
        self.assertGreater(finite_normalizer(sigma, 12), 0)
        self.assertGreater(omitted_unnormalized_mass_upper_bound(sigma, 12), 0)

    def test_product_bound_accumulates_coordinates(self):
        one = truncation_tv_upper_bound(Decimal("2"), 8)
        self.assertEqual(
            gaussian_product_tv_upper_bound(Decimal("2"), 8, 0), Decimal(0)
        )
        self.assertLessEqual(
            gaussian_product_tv_upper_bound(Decimal("2"), 8, 4),
            min(Decimal(1), 4 * one),
        )

    def test_conditioned_bound_is_conservative(self):
        self.assertEqual(
            conditioned_tv_upper_bound(Decimal("0.01"), Decimal("0.5")),
            Decimal("0.04"),
        )

    def test_inverse_cdf_grid_bound(self):
        self.assertEqual(inverse_cdf_grid_tv_upper_bound(3, 2), Decimal("0.75"))

    def test_union_validation(self):
        with self.assertRaises(StatisticalDistanceError):
            product_tv_union_bound((Decimal("1.1"),))
        with self.assertRaises(StatisticalDistanceError):
            conditioned_tv_upper_bound(Decimal("0.1"), Decimal(0))


if __name__ == "__main__":
    unittest.main()
