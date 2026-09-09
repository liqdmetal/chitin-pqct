"""Tests for the computed SHVZK bound.

The load-bearing finding: at the codebase's 6-sigma default the SHVZK
bound is 2^-15 -- NOT zero-knowledge in any usable sense -- and it is
truncation-dominated. The fix is the same ~12.3-sigma tail that
truncation_distance derived independently. Two modules, one number.
"""

import math
import unittest

from pqct.shvzk_bound import (
    LEMMA6_LOG2_DISTANCE,
    ResponseFamily,
    SHVZKBound,
    assessment,
    paper_profile_bound,
    required_tail_multiplier_for,
)


class BoundArithmeticTests(unittest.TestCase):
    def test_family_bound_is_per_coord_times_coords(self):
        fam = ResponseFamily("f", 1024, 100.0, 1236)   # ~12.4 sigma
        expected = fam.per_coord_log2 + math.log2(1024)
        self.assertAlmostEqual(fam.family_log2, expected, places=9)

    def test_total_sums_families(self):
        a = ResponseFamily("a", 100, 10.0, 124)
        b = ResponseFamily("b", 200, 10.0, 124)
        bound = SHVZKBound((a, b))
        expected = math.log2(2 ** a.family_log2 + 2 ** b.family_log2)
        self.assertAlmostEqual(bound.total_log2, expected, places=9)
        self.assertEqual(bound.total_coordinates, 300)

    def test_lemma6_floor_is_minus_100_plus_log_coords(self):
        bound = paper_profile_bound(12.35)
        self.assertAlmostEqual(
            bound.lemma6_only_log2,
            LEMMA6_LOG2_DISTANCE + math.log2(bound.total_coordinates),
            places=9,
        )

    def test_commitments_add_zero(self):
        """Data-processing: commitments are a function of responses."""
        bound = paper_profile_bound(12.35)
        self.assertEqual(bound.summary()["commitment_contribution"],
                         "0 (data-processing inequality)")


class TheFindingTests(unittest.TestCase):
    """SHVZK at the 6-sigma default is NOT zero-knowledge."""

    def test_default_tail_gives_useless_bound(self):
        bound = paper_profile_bound(6.0)
        self.assertGreater(bound.total_log2, -20.0,
                           "6 sigma leaves a ~2^-15 distinguisher")
        self.assertTrue(bound.truncation_dominates)

    def test_required_tail_matches_truncation_module(self):
        """Independent derivation must land on ~12.25-12.4 sigma."""
        needed = required_tail_multiplier_for(-100.0, 15872)
        self.assertGreater(needed, 12.0)
        self.assertLess(needed, 12.6)

    def test_required_tail_restores_lemma6_floor(self):
        needed = required_tail_multiplier_for(-100.0, 15872)
        bound = paper_profile_bound(needed)
        self.assertFalse(bound.truncation_dominates)
        self.assertLess(bound.total_log2, -85.0)
        # Within ~1 bit of the pure Lemma-6 floor.
        self.assertLess(abs(bound.total_log2 - bound.lemma6_only_log2), 1.5)

    def test_paper_profile_coordinate_count(self):
        """S*k*d + 2*m*d = 2*64*64 + 2*60*64 = 15872."""
        self.assertEqual(paper_profile_bound(6.0).total_coordinates, 15872)


class HonestyTests(unittest.TestCase):
    def test_lemma6_constant_is_flagged_as_cited(self):
        status = assessment()["status"]
        self.assertIn("cited constant", status)
        self.assertIn("not re-derived", status)

    def test_finding_names_the_convergence(self):
        finding = assessment()["finding"]
        self.assertIn("truncation_distance", finding)
        self.assertIn("SAME parameter", finding)

    def test_bounded_not_estimated(self):
        self.assertIn("BOUNDED, not estimated", assessment()["status"])


if __name__ == "__main__":
    unittest.main()
