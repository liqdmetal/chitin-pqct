"""Tests for the mixed per-column bound M-SIS bracket.

The substantive checks: the volume arithmetic is right, the two extremes
bracket in the expected direction, and the counting slack is NOT converted
into bits (the mistake that caused a false alarm earlier in this repo).
"""

import math
import unittest

from pqct.mixed_bound_msis import (
    ColumnBlock,
    analyze_mixed_bounds,
    paper_mixed_bounds,
)
from pqct.msis_hardness import HardnessError

Q_PAPER = 2 ** 49 - 2 ** 18 + 2 ** 9 + 1


class ColumnBlockTests(unittest.TestCase):
    def test_box_volume_is_log2_of_2b_plus_1_to_the_columns(self):
        block = ColumnBlock("x", 10, 2.0, "r")
        self.assertAlmostEqual(block.log2_box_volume, 10 * math.log2(5.0), places=12)

    def test_bit_block_uses_three_values(self):
        """dm in {-1,0,1} means 3 values per coefficient, not 2."""
        block = ColumnBlock("bits", 1, 1.0, "r")
        self.assertAlmostEqual(block.log2_box_volume, math.log2(3.0), places=12)

    def test_rejects_bad_blocks(self):
        with self.assertRaises(HardnessError):
            ColumnBlock("x", 0, 1.0, "r")
        with self.assertRaises(HardnessError):
            ColumnBlock("x", 10, 0.0, "r")


class PaperMixedBoundTests(unittest.TestCase):
    def setUp(self):
        self.report = paper_mixed_bounds()

    def test_block_structure_matches_the_hmc(self):
        """64 message columns (k=v=64) and 60 randomness columns, times d."""
        names = {b.name: b for b in self.report.blocks}
        self.assertEqual(names["message (dm)"].columns, 64 * 64)
        self.assertEqual(names["message (dm)"].bound, 1.0)
        self.assertEqual(names["randomness (dr)"].columns, 60 * 64)
        self.assertEqual(names["randomness (dr)"].bound, 2.0)
        self.assertEqual(self.report.total_columns, 7936)

    def test_tight_extreme_is_off_scale_hard(self):
        """beta=2 needs delta ~ 1.0000019, unreachable by bounded BKZ.

        This is the honest content of that extreme: not a bit figure, but
        'astronomically hard'. Reporting nan-nan bits (as an earlier version
        did) would have looked like a bug instead of a finding.
        """
        self.assertIn("unreachable", self.report.tight_verdict)
        self.assertIn("off-scale hard", self.report.tight_verdict)

    def test_relaxed_extreme_matches_the_msis_module(self):
        self.assertIn("92-117", self.report.relaxed_verdict)

    def test_slack_is_hugely_negative(self):
        """The true box is nowhere near containing a guaranteed solution,
        which is evidence the 92-117 range is a conservative FLOOR."""
        self.assertLess(self.report.slack_bits, -10_000.0)
        self.assertFalse(self.report.solutions_abundant_by_counting)

    def test_equivalent_scalar_lies_between_the_block_bounds(self):
        """The volume-equivalent uniform bound must sit between 1 and 2."""
        self.assertGreater(self.report.equivalent_uniform_bound, 1.0)
        self.assertLess(self.report.equivalent_uniform_bound, 2.0)

    def test_slack_is_not_presented_as_bits_of_security(self):
        summary = self.report.summary()
        self.assertIn("slack_bits_counting", summary)
        self.assertNotIn("slack_bits_security", summary)
        self.assertIn("COUNTING statement", summary["status"])
        self.assertIn("not", summary["status"].lower())

    def test_status_is_open(self):
        self.assertIn("OPEN", self.report.summary()["status"])

    def test_interval_names_both_directions(self):
        interval = self.report.interval_description
        self.assertIn("overstates security", interval)
        self.assertIn("understates", interval)


class MixedBoundArithmeticTests(unittest.TestCase):
    def test_volume_sums_over_blocks(self):
        blocks = (
            ColumnBlock("a", 100, 1.0, "r"),
            ColumnBlock("b", 200, 3.0, "r"),
        )
        report = analyze_mixed_bounds(
            blocks=blocks, n_module=2, d=4, q=Q_PAPER, relaxed_bound=1000.0
        )
        expected = 100 * math.log2(3.0) + 200 * math.log2(7.0)
        self.assertAlmostEqual(
            report.slack_bits, expected - 8 * math.log2(Q_PAPER), places=6
        )

    def test_wider_bounds_increase_slack(self):
        narrow = analyze_mixed_bounds(
            blocks=(ColumnBlock("a", 100, 1.0, "r"),),
            n_module=1, d=4, q=Q_PAPER, relaxed_bound=1000.0,
        )
        wide = analyze_mixed_bounds(
            blocks=(ColumnBlock("a", 100, 50.0, "r"),),
            n_module=1, d=4, q=Q_PAPER, relaxed_bound=1000.0,
        )
        self.assertGreater(wide.slack_bits, narrow.slack_bits)

    def test_relaxed_bound_at_or_above_q_is_flagged(self):
        report = analyze_mixed_bounds(
            blocks=(ColumnBlock("a", 100, 1.0, "r"),),
            n_module=29, d=64, q=Q_PAPER,
            relaxed_bound=float(Q_PAPER) * 2,
        )
        self.assertIn(">= q", report.relaxed_verdict)

    def test_rejects_empty_blocks(self):
        with self.assertRaises(HardnessError):
            analyze_mixed_bounds(
                blocks=(), n_module=29, d=64, q=Q_PAPER, relaxed_bound=100.0
            )

    def test_rejects_bad_ring_parameters(self):
        with self.assertRaises(HardnessError):
            analyze_mixed_bounds(
                blocks=(ColumnBlock("a", 10, 1.0, "r"),),
                n_module=0, d=64, q=Q_PAPER, relaxed_bound=100.0,
            )


if __name__ == "__main__":
    unittest.main()
