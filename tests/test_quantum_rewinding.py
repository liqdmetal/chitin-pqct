"""Tests for the quantum-rewinding discharge.

The discharge is "DFM'20 Cor.13 applies", which is only true if its
hypotheses hold for THIS protocol. Each hypothesis is pinned so a future
change that breaks one (e.g. dropping zeta from x's hash input) fails
loudly here rather than silently invalidating the QROM bound.
"""

from __future__ import annotations

import unittest

from pqct.quantum_rewinding import (
    all_hypotheses,
    check_h2_ordered_hashing,
    check_h4_additive_error,
    check_h6_interactive_knowledge_soundness,
    quantum_rewinding_report,
)


class HypothesisTests(unittest.TestCase):
    def test_all_six_hold(self):
        hs = all_hypotheses()
        self.assertEqual(len(hs), 6)
        for h in hs:
            self.assertTrue(h.holds, f"{h.name} failed: {h.evidence}")

    def test_h2_is_load_bearing_and_reads_the_code(self):
        """H2 (zeta bound into x's hash) is the mFS ordering hypothesis and
        the one most likely to be broken by a refactor. It must be checked
        against the SOURCE, not asserted."""
        h = check_h2_ordered_hashing()
        self.assertTrue(h.holds)
        self.assertIn("prior=(zeta.encode(),)", h.evidence)

    def test_h4_additive_error_is_tiny(self):
        h = check_h4_additive_error()
        self.assertTrue(h.holds)
        self.assertIn("-255", h.evidence)

    def test_h6_depends_on_special_soundness(self):
        """The quantum route needs only CLASSICAL knowledge soundness of the
        interactive protocol, which is what special_soundness delivers."""
        h = check_h6_interactive_knowledge_soundness()
        self.assertTrue(h.holds)
        self.assertIn("counterexamples=[]", h.evidence)


class HonestyTests(unittest.TestCase):
    def test_route_says_rewinding_is_routed_around_not_fixed(self):
        r = quantum_rewinding_report()
        self.assertIn("does NOT transfer", r["route"])
        self.assertIn("ROUTES AROUND", r["route"])
        self.assertIn("TIGHT", r["route"])

    def test_collapsing_is_explicitly_not_claimed(self):
        r = quantum_rewinding_report()
        self.assertIn("No collapsing", r["not_claimed"])
        self.assertIn("Reopens if used interactively", r["not_claimed"])

    def test_status_discharged_with_caveat(self):
        s = quantum_rewinding_report()["status"]
        self.assertIn("DISCHARGED", s)
        self.assertIn("not a written proof", s)


if __name__ == "__main__":
    unittest.main()
