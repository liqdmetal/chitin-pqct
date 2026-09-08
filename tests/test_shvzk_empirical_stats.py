import unittest

from pqct.shvzk_empirical_stats import EmpiricalStatsError, collision_aware_stats


class SHVZKEmpiricalStatsTests(unittest.TestCase):
    def test_prefix_binning_reveals_collisions(self):
        left = (b"aa0", b"aa1", b"ab0", b"ab1")
        right = (b"aa2", b"aa3", b"ab2", b"ab3")
        stats = collision_aware_stats(left, right, prefix_bytes=2)
        self.assertEqual(stats.bins, 2)
        self.assertEqual(stats.left_distinct, 2)
        self.assertEqual(stats.right_distinct, 2)
        self.assertEqual(stats.exact_histogram_tv, 1)
        self.assertEqual(stats.collision_probability_left, stats.collision_probability_right)

    def test_empty_input_rejected(self):
        with self.assertRaises(EmpiricalStatsError):
            collision_aware_stats((), (b"x",))

    def test_entropy_bound_is_nonnegative(self):
        stats = collision_aware_stats((b"a", b"a", b"b"), (b"a", b"b", b"b"))
        self.assertGreaterEqual(stats.left_min_entropy_lower_bound, 0)
        self.assertGreaterEqual(stats.right_min_entropy_lower_bound, 0)


if __name__ == "__main__":
    unittest.main()
