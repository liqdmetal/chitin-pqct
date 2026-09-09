"""Tests for the non-adaptive zeta round-reduction attempt.

The pair that matters: the CURRENT derivation is demonstrably grindable
(commitment mutations steer zeta), and the statement-bound derivation is
not. That is the structural precondition for dropping mu from 2 to 1.
"""

import unittest

from pqct.hmc import bounded_ring_element
from pqct.nonadaptive_zeta import (
    NonAdaptiveZetaError,
    derive_statement_bound_zeta,
    grinding_resistance,
    residual_soundness_question,
    round_reduction_saving,
)
from pqct.ring_challenge import RingChallengeParameters
from pqct.ring_commitment import ToyParameters


class StatementBoundZetaTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.r = lambda v: bounded_ring_element(v, self.params)
        self.cp = RingChallengeParameters(4, 2)

    def test_deterministic_for_one_statement(self):
        first = derive_statement_bound_zeta(b"stmt", self.params, self.cp)
        second = derive_statement_bound_zeta(b"stmt", self.params, self.cp)
        self.assertEqual(first, second)

    def test_different_statements_give_different_zetas(self):
        a = derive_statement_bound_zeta(b"stmt-a", self.params, self.cp)
        b = derive_statement_bound_zeta(b"stmt-b", self.params, self.cp)
        self.assertNotEqual(a, b)

    def test_empty_statement_refused(self):
        with self.assertRaises(NonAdaptiveZetaError):
            derive_statement_bound_zeta(b"", self.params, self.cp)

    def test_zeta_is_a_valid_ring_element(self):
        zeta = derive_statement_bound_zeta(b"stmt", self.params, self.cp)
        self.assertEqual(zeta.params, self.params)
        self.assertEqual(len(zeta.coeffs), self.params.n)


class GrindingTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda v: bounded_ring_element(v, self.params)
        self.cp = RingChallengeParameters(4, 2)
        self.variants = [
            ((r((i, 0, 0, 0, 0, 0, 0, 0)), r((i + 1, 0, 0, 0, 0, 0, 0, 0))),)
            for i in range(20)
        ]

    def test_current_adaptive_derivation_is_grindable(self):
        """Hashing commitments into zeta lets the prover steer it: 20
        variants under ONE statement reach 20 distinct zetas."""
        report = grinding_resistance(
            b"stmt", self.params, self.cp, self.variants, adaptive=True
        )
        self.assertEqual(report.distinct_zetas, 20)
        self.assertTrue(report.steerable)
        self.assertIn("GRINDABLE", report.summary()["verdict"])

    def test_statement_bound_derivation_is_not_grindable(self):
        report = grinding_resistance(
            b"stmt", self.params, self.cp, self.variants, adaptive=False
        )
        self.assertEqual(report.distinct_zetas, 1)
        self.assertFalse(report.steerable)
        self.assertIn("NOT GRINDABLE", report.summary()["verdict"])

    def test_no_variants_refused(self):
        with self.assertRaises(NonAdaptiveZetaError):
            grinding_resistance(b"stmt", self.params, self.cp, [])

    def test_single_variant_is_trivially_unsteerable(self):
        """Guard against a false pass: one variant always gives one zeta,
        so the test above needs MANY variants to mean anything."""
        report = grinding_resistance(
            b"stmt", self.params, self.cp, self.variants[:1], adaptive=True
        )
        self.assertEqual(report.distinct_zetas, 1)
        self.assertFalse(report.steerable)


class SavingTests(unittest.TestCase):
    def test_saving_is_320_bits_at_2_64(self):
        saving = round_reduction_saving(2 ** 64)
        self.assertAlmostEqual(saving["saving_bits"], 320.0, delta=1.0)
        self.assertEqual(saving["before"]["challenges"], 2)
        self.assertEqual(saving["after"]["challenges"], 1)
        self.assertEqual(saving["before"]["leaves"], 6)
        self.assertEqual(saving["after"]["leaves"], 3)

    def test_saving_scales_with_query_budget(self):
        self.assertLess(
            round_reduction_saving(2 ** 32)["saving_bits"],
            round_reduction_saving(2 ** 64)["saving_bits"],
        )


class HonestyTests(unittest.TestCase):
    def test_residual_question_is_open_and_specific(self):
        question = residual_soundness_question()
        self.assertIn("OPEN", question["status"])
        self.assertIn("cancellation", question["question"])
        self.assertEqual(question["value_if_resolved_bits"], 320.0)

    def test_both_sides_of_the_question_are_argued(self):
        question = residual_soundness_question()
        self.assertIn("hash-inversion", question["why_it_might_be_fine"])
        self.assertIn("relation-specific", question["why_it_might_not_be"])

    def test_attempt_does_not_claim_the_saving_is_realised(self):
        """The 320 bits are CONDITIONAL. Nothing here may claim otherwise."""
        question = residual_soundness_question()
        self.assertIn("required", question["status"].lower() + question["who"])


if __name__ == "__main__":
    unittest.main()
