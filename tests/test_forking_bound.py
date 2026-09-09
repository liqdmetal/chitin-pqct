"""Tests for the computed forking bound.

Pins the arithmetic of the Attema-Fehr-Kloss bound and, more importantly,
pins the 512-bit correction against the placeholder so the wrong formula
cannot creep back. Also pins that the classical/QROM gap is reported as a
gap rather than collapsed to the optimistic figure.
"""

import math
import unittest

from pqct.forking_bound import (
    ForkingError,
    TreeShape,
    chitin_tree,
    forking_report,
    fs_knowledge_error_classical,
    fs_knowledge_error_qrom_conservative,
    interactive_knowledge_error,
    placeholder_loss_bits,
)


class TreeShapeTests(unittest.TestCase):
    def test_chitin_tree_is_2_by_3(self):
        shape = chitin_tree()
        self.assertEqual(shape.branching, (2, 3))
        self.assertEqual(shape.rounds, 2)
        self.assertEqual(shape.leaves, 6)

    def test_branching_below_two_rejected(self):
        with self.assertRaises(ForkingError):
            TreeShape(branching=(1, 3), challenge_sizes=(2 ** 256, 2 ** 256))

    def test_challenge_set_smaller_than_branching_rejected(self):
        with self.assertRaises(ForkingError):
            TreeShape(branching=(5,), challenge_sizes=(4,))

    def test_misaligned_lengths_rejected(self):
        with self.assertRaises(ForkingError):
            TreeShape(branching=(2, 3), challenge_sizes=(2 ** 256,))


class KnowledgeErrorTests(unittest.TestCase):
    def test_single_round_matches_closed_form(self):
        """One round, k=2, |C|=2^10: kappa = 1/2^10 exactly."""
        shape = TreeShape(branching=(2,), challenge_sizes=(2 ** 10,))
        self.assertAlmostEqual(interactive_knowledge_error(shape), -10.0, places=6)

    def test_two_rounds_sum_for_tiny_p(self):
        """kappa ~ sum (k_i-1)/|C_i| when each term is tiny.
        (2-1)/2^256 + (3-1)/2^256 = 3/2^256 -> log2 = log2(3) - 256."""
        shape = chitin_tree()
        expected = math.log2(3) - math.log2(shape.challenge_sizes[0])
        self.assertAlmostEqual(interactive_knowledge_error(shape), expected, places=3)

    def test_classical_fs_adds_exactly_log2_q_plus_one(self):
        shape = chitin_tree()
        base = interactive_knowledge_error(shape)
        for q in (2 ** 32, 2 ** 64):
            self.assertAlmostEqual(
                fs_knowledge_error_classical(shape, q) - base, math.log2(q + 1), places=9
            )

    def test_qrom_loss_is_2mu_times_log2_2q_plus_1(self):
        shape = chitin_tree()
        base = interactive_knowledge_error(shape)
        q = 2 ** 64
        self.assertAlmostEqual(
            fs_knowledge_error_qrom_conservative(shape, q) - base,
            2 * 2 * math.log2(2 * q + 1), places=9,
        )

    def test_zero_queries_rejected(self):
        with self.assertRaises(ForkingError):
            fs_knowledge_error_classical(chitin_tree(), 0)


class CorrectionTests(unittest.TestCase):
    """The substantive finding: the placeholder was 512 bits too pessimistic."""

    def test_placeholder_formula_reproduced(self):
        shape = chitin_tree()
        self.assertAlmostEqual(placeholder_loss_bits(shape, 2 ** 64), 5 * 64 + 4 * 64)

    def test_classical_residual_is_about_190_bits(self):
        report = forking_report(2 ** 64)
        self.assertAlmostEqual(report.classical_fs_bits, 190.5, delta=1.0)

    def test_placeholder_was_off_by_512_bits(self):
        report = forking_report(2 ** 64)
        gap = report.classical_fs_bits - report.placeholder_residual_bits
        self.assertAlmostEqual(gap, 512.0, delta=1.0)

    def test_classical_loss_is_log2_q_once_not_per_leaf(self):
        """AFK'22's whole point: the loss is a single factor (Q+1)."""
        report = forking_report(2 ** 64)
        self.assertAlmostEqual(report.classical_loss_bits, 64.0, delta=0.01)

    def test_qrom_conservative_is_much_worse_than_classical(self):
        """The two figures must be reported as a gap, not averaged."""
        report = forking_report(2 ** 64)
        self.assertGreater(report.classical_fs_bits - report.qrom_fs_bits, 150)

    def test_classical_stays_positive_across_realistic_q(self):
        for lq in (32, 48, 64, 80, 96):
            self.assertGreater(forking_report(2 ** lq).classical_fs_bits, 100)

    def test_qrom_conservative_crosses_zero_near_2_to_64(self):
        """Documents where the pessimistic quantum bound runs out."""
        self.assertGreater(forking_report(2 ** 48).qrom_fs_bits, 0)
        self.assertLess(forking_report(2 ** 80).qrom_fs_bits, 0)


class HonestyTests(unittest.TestCase):
    def test_summary_states_the_conditional(self):
        summary = forking_report().summary()
        self.assertIn("special-soundness", summary["conditional_on"])
        self.assertIn("open obligation", summary["conditional_on"])

    def test_summary_names_both_theorems(self):
        summary = forking_report().summary()
        self.assertIn("Attema-Fehr-Kloss", summary["classical_fs"]["theorem"])
        self.assertIn("measure-and-reprogram", summary["qrom_fs_conservative"]["theorem"])


if __name__ == "__main__":
    unittest.main()
