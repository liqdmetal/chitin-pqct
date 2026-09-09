"""Tests for the multi-round Fiat-Shamir structure analysis.

The substantive test is test_implemented_protocol_has_two_challenges: it
reads the round structure off the actual derivation functions, which is what
caught the earlier analysis being for a three-move protocol.
"""

import inspect
import math
import unittest

from pqct import binary_protocol1_ring
from pqct.multiround_qrom import (
    RoundStructure,
    RoundStructureError,
    chitin_round_structure,
    compare_losses,
    round_reduction_options,
    three_move_structure,
)


class RoundStructureTests(unittest.TestCase):
    def test_moves_is_two_challenges_plus_one(self):
        self.assertEqual(three_move_structure().moves, 3)
        self.assertEqual(chitin_round_structure().moves, 5)

    def test_extraction_leaves_multiply_across_rounds(self):
        self.assertEqual(chitin_round_structure().extraction_leaves, 6)
        self.assertEqual(three_move_structure().extraction_leaves, 3)
        self.assertEqual(
            RoundStructure(3, (2, 3, 4), "x").extraction_leaves, 24
        )

    def test_forking_loss_is_leaves_minus_one_log_q(self):
        structure = chitin_round_structure()
        self.assertAlmostEqual(
            structure.forking_loss_bits(2 ** 64), 5 * 64.0, places=6
        )

    def test_qrom_loss_is_two_mu_log_q(self):
        self.assertAlmostEqual(
            chitin_round_structure().qrom_loss_bits(2 ** 64), 4 * 64.0, places=6
        )
        self.assertAlmostEqual(
            three_move_structure().qrom_loss_bits(2 ** 64), 2 * 64.0, places=6
        )

    def test_rejects_degenerate_structures(self):
        with self.assertRaises(RoundStructureError):
            RoundStructure(0, (), "x")
        with self.assertRaises(RoundStructureError):
            RoundStructure(2, (3,), "x")  # branch count mismatch
        with self.assertRaises(RoundStructureError):
            RoundStructure(1, (1,), "x")  # one branch cannot extract
        with self.assertRaises(RoundStructureError):
            chitin_round_structure().forking_loss_bits(0)


class StructureIdentificationTests(unittest.TestCase):
    """Read the round structure off the real code, not off a doc claim."""

    def test_implemented_protocol_has_two_challenges(self):
        """_derive_zeta and _derive_x are BOTH hash-derived challenges, and
        x depends on zeta, so there are two sequential Fiat-Shamir rounds."""
        self.assertTrue(hasattr(binary_protocol1_ring, "_derive_zeta"))
        self.assertTrue(hasattr(binary_protocol1_ring, "_derive_x"))
        x_source = inspect.getsource(binary_protocol1_ring._derive_x)
        # x is derived with zeta as prior input -> sequential dependence.
        self.assertIn("zeta", x_source)
        self.assertIn("prior", x_source)

    def test_zeta_is_derived_from_the_first_message(self):
        """zeta hashes bit_commitments but NOT the E/F/G commitments."""
        source = inspect.getsource(binary_protocol1_ring._derive_zeta)
        self.assertIn("bit_commitments", source)
        # empty proof_commitments tuple -> first-message only
        self.assertIn("()", source)

    def test_x_is_derived_from_the_second_message(self):
        source = inspect.getsource(binary_protocol1_ring._derive_x)
        self.assertIn("proof_commitments", source)

    def test_family_builder_agrees_it_is_a_tree(self):
        """pqct/protocol1_family.py builds a 2 zeta x 3 x tree, which is
        independent evidence of a two-challenge structure."""
        from pqct import protocol1_family

        source = inspect.getsource(protocol1_family)
        self.assertIn("zeta", source)
        self.assertIn("three distinct x challenges", source)


class CorrectionTests(unittest.TestCase):
    """The earlier figures were for the wrong protocol."""

    def test_correction_is_severe(self):
        comparison = compare_losses(queries=2 ** 64)
        self.assertAlmostEqual(comparison.assumed_residual, 0.0, delta=1.0)
        self.assertAlmostEqual(comparison.actual_residual, -320.0, delta=1.0)
        self.assertAlmostEqual(comparison.correction_bits, 320.0, delta=1.0)

    def test_actual_residual_is_negative_at_every_realistic_q(self):
        for log_q in (32, 48, 64, 80):
            with self.subTest(log_q=log_q):
                self.assertLess(
                    compare_losses(queries=2 ** log_q).actual_residual, 0.0
                )

    def test_verdict_names_the_structural_cause(self):
        verdict = compare_losses().summary()["verdict"]
        self.assertIn("THREE-MOVE", verdict)
        self.assertIn("two Fiat-Shamir challenges", verdict)

    def test_five_move_loses_more_than_three_move(self):
        queries = 2 ** 64
        self.assertGreater(
            chitin_round_structure().total_loss_bits(queries),
            three_move_structure().total_loss_bits(queries),
        )


class ReductionOptionTests(unittest.TestCase):
    def test_three_options_with_honest_status(self):
        options = round_reduction_options()
        self.assertEqual(len(options), 3)
        statuses = [o["status"] for o in options]
        self.assertTrue(any("NOT ATTEMPTED" in s for s in statuses))
        self.assertTrue(any("current state" in s for s in statuses))

    def test_each_option_states_a_cost(self):
        for option in round_reduction_options():
            with self.subTest(option=option["option"]):
                self.assertTrue(option["cost"])
                self.assertIn("saving_bits_at_2_64", option)

    def test_removing_a_round_saves_five_log_q(self):
        """mu 2->1 saves 2*log2(Q) QROM plus 3*log2(Q) forking."""
        for option in round_reduction_options():
            if "constant" in option["option"]:
                self.assertAlmostEqual(
                    option["saving_bits_at_2_64"], 5 * 64.0, places=6
                )


if __name__ == "__main__":
    unittest.main()
