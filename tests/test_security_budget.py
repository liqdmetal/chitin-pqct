"""Tests for the end-to-end security budget.

Pins both the arithmetic (minimum over components, minus losses) and the
honesty properties: an unanalysed component must block a claim, and the
budget must never present a residual as a security level while anything is
open.
"""

import math
import unittest

from pqct.security_budget import (
    BudgetError,
    Certification,
    Component,
    Loss,
    SecurityBudget,
    default_components,
    default_losses,
    mlwe_component,
    msis_component,
    paper_budget,
    signature_component,
)


class ComponentTests(unittest.TestCase):
    def test_rejects_inverted_range(self):
        with self.assertRaises(BudgetError):
            Component("bad", 100.0, 50.0, Certification.COMPUTED_EXACT, "x")

    def test_every_component_is_now_certified(self):
        """M-LWE was the last UNANALYSED component; pqct/mlwe_hardness.py
        closed it, so nothing should be uncertified now."""
        self.assertTrue(mlwe_component().certified)
        self.assertTrue(msis_component().certified)
        self.assertTrue(signature_component().certified)
        self.assertEqual(paper_budget().uncertified_components, ())

    def test_mlwe_basis_documents_the_sample_limit_and_caveats(self):
        basis = mlwe_component().basis
        self.assertIn("SAMPLE-LIMITED", basis)
        self.assertIn("NOT certified", basis)
        self.assertIn("hybrid", basis)

    def test_mlwe_and_msis_are_comparable(self):
        """The paper's m~2n balancing: neither should dominate."""
        mlwe, msis = mlwe_component(), msis_component()
        self.assertLess(abs(mlwe.bits_low - msis.bits_low), 10.0)

    def test_msis_range_matches_the_hardness_module(self):
        component = msis_component()
        self.assertAlmostEqual(component.bits_low, 91.5, places=1)
        self.assertAlmostEqual(component.bits_high, 117.3, places=1)
        self.assertTrue(component.is_range)

    def test_signature_is_flagged_as_external_not_ours(self):
        component = signature_component()
        self.assertEqual(component.certification, Certification.EXTERNAL_STANDARD)
        self.assertIn("FIPS 204", component.basis)


class BudgetArithmeticTests(unittest.TestCase):
    def test_minimum_ignores_uncertified_components(self):
        """The unanalysed M-LWE term is 0 bits but must not drag the
        minimum to 0 -- it blocks the CLAIM instead, which is the honest
        treatment of 'unknown' versus 'known to be weak'."""
        budget = paper_budget()
        self.assertGreater(budget.minimum_low, 0.0)
        self.assertAlmostEqual(budget.minimum_low, 91.5, places=1)

    def test_capped_by_the_weakest_certified_component(self):
        self.assertEqual(paper_budget().binding_component.name, "M-SIS binding")

    def test_total_loss_sums_the_losses(self):
        """Total = classical AFK'22 (64) + QROM-beyond-classical (195) +
        truncation/ZK leak. The leak tracks the SHIPPED sampler tail
        (ZK_TAIL_SIGMAS): at the old 6-sigma default it was ~85 (a 2^-15
        leak); at the shipped 13 sigma the SHVZK bound sits at the Lemma-6
        floor 2^-86 and the leak reads ~14. Pin the sum identity and pin
        that the leak reflects the fix, not the old default."""
        budget = paper_budget(quantum_queries=2 ** 64)
        self.assertAlmostEqual(
            budget.total_loss, sum(l.bits for l in budget.losses), places=6
        )
        leak = next(l for l in budget.losses if "ZK leak" in l.name)
        self.assertLess(leak.bits, 20.0, "13-sigma tail must have closed the leak")
        self.assertGreater(leak.bits, 10.0, "Lemma-6 floor ~14 must still be visible")

    def test_residual_is_minimum_minus_loss(self):
        budget = paper_budget()
        self.assertAlmostEqual(
            budget.residual_low, budget.minimum_low - budget.total_loss, places=6
        )

    def test_losses_scale_with_query_budget(self):
        small = paper_budget(quantum_queries=2 ** 32)
        large = paper_budget(quantum_queries=2 ** 80)
        self.assertLess(small.total_loss, large.total_loss)
        self.assertGreater(small.residual_low, large.residual_low)


class HonestyTests(unittest.TestCase):
    def test_not_claimable_with_an_unanalysed_component(self):
        self.assertFalse(paper_budget().claimable)

    def test_verdict_names_every_blocker(self):
        verdict = paper_budget().verdict
        self.assertIn("NO CLAIM", verdict)
        # Every component is certified and BOTH FS losses are now established
        # (AFK'22 classical, DFM'20 QROM -- the latter TIGHT). The ONLY
        # remaining blocker is the negative residual itself.
        self.assertNotIn("uncertified component", verdict)
        self.assertNotIn("unestablished", verdict)
        self.assertIn("non-positive", verdict)

    def test_certification_is_a_gate_independent_of_arithmetic(self):
        """A comfortable residual must NOT unlock a claim while ANY
        component is unanalysed. Uses an explicit unanalysed component now
        that M-LWE is closed, so the property is tested on its own terms."""
        components = (
            msis_component(),
            Component("hypothetical unknown", 0.0, 0.0,
                      Certification.UNANALYSED, "nobody has looked"),
            signature_component(),
        )
        budget = SecurityBudget(
            components=components,
            losses=(Loss("none", 0.0, "no loss", True),),
        )
        self.assertGreater(budget.residual_low, 0.0)
        self.assertFalse(budget.claimable, "unanalysed component must block")
        self.assertIn("hypothetical unknown", budget.verdict)

    def test_becomes_claimable_only_when_everything_is_closed(self):
        """Documents the exact conditions: all certified, all losses
        established, residual positive."""
        components = (
            msis_component(),
            Component("M-LWE hiding", 120.0, 120.0,
                      Certification.TWO_METHODS_AGREE, "hypothetical"),
            signature_component(),
        )
        budget = SecurityBudget(
            components=components,
            losses=(Loss("small", 10.0, "hypothetical", True),),
        )
        self.assertTrue(budget.claimable)
        self.assertIn("external review", budget.verdict)

    def test_unestablished_loss_alone_blocks_a_claim(self):
        components = (
            msis_component(),
            Component("M-LWE hiding", 120.0, 120.0,
                      Certification.TWO_METHODS_AGREE, "hypothetical"),
        )
        budget = SecurityBudget(
            components=components,
            losses=(Loss("guess", 5.0, "not established", False),),
        )
        self.assertFalse(budget.claimable)
        self.assertIn("unestablished", budget.verdict)

    def test_summary_reports_no_claim(self):
        summary = paper_budget().summary()
        self.assertFalse(summary["claimable"])
        self.assertIn("NO CLAIM", summary["verdict"])
        self.assertEqual(summary["capped_by"], "M-SIS binding")

    def test_truncation_loss_is_established(self):
        """The one loss this repo actually closed."""
        truncation = next(
            l for l in default_losses() if "truncation" in l.name
        )
        self.assertTrue(truncation.established)


if __name__ == "__main__":
    unittest.main()
