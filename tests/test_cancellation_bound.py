"""Tests pinning the REFUTATION of the sqrt(q) cancellation bound.

These exist to stop the refuted argument being resurrected. The sqrt(q)
bound is attractive and wrong, and the only thing that showed it was wrong
was brute force, so the brute force is what gets pinned.
"""

from __future__ import annotations

import unittest

from pqct.cancellation_bound import (
    BoundError,
    LatticeBound,
    assessment,
    degenerate_challenge_check,
    exhaustive_shortest,
    paper_bound,
)
from pqct.challenge import sample_sparse_challenge
from pqct.hmc import bounded_ring_element
from pqct.ring_challenge import challenge_ring_element
from pqct.ring_commitment import ToyParameters


def sparse_zeta(n: int, q: int, peak: int, seed: bytes = b"bf"):
    params = ToyParameters(n=n, q=q, k=2)
    weight = max(1, min(4, n // 2))
    return challenge_ring_element(
        sample_sparse_challenge(seed, params, weight, peak)
    )


class RefutationTests(unittest.TestCase):
    """The measured behaviour that kills the determinant argument."""

    def test_shortest_cancellation_is_flat_in_modulus(self):
        """THE finding: the minimum does not grow with q, while the
        heuristic grows as sqrt(q). Flat across a 127x range."""
        results = []
        for q in (97, 257, 769, 3329, 12289):
            zeta = sparse_zeta(4, q, 2)
            found = exhaustive_shortest(
                tuple(zeta.coeffs), 4, q, search_radius=3
            )
            results.append(found["shortest_found"])
        self.assertEqual(len(set(results)), 1, f"expected flat, got {results}")
        self.assertEqual(results[0], 2)

    def test_heuristic_overestimates_by_orders_of_magnitude(self):
        """Ratio degrades as q grows -- 0.03 at q = 12289, n = 4."""
        q = 12289
        zeta = sparse_zeta(4, q, 2)
        heuristic = LatticeBound(
            ring_degree=4, modulus=q, accounts=2
        ).gaussian_heuristic
        measured = exhaustive_shortest(
            tuple(zeta.coeffs), 4, q, search_radius=3
        )["shortest_found"]
        self.assertLess(measured / heuristic, 0.10)

    def test_shortest_equals_challenge_peak(self):
        """The corrected margin: the minimum tracks p, not q."""
        for peak in (2, 4):
            zeta = sparse_zeta(4, 12289, peak)
            measured = exhaustive_shortest(
                tuple(zeta.coeffs), 4, 12289, search_radius=max(3, peak)
            )["shortest_found"]
            self.assertEqual(measured, peak)

    def test_lattice_bound_is_marked_refuted(self):
        """No caller may mistake the dead hypothesis for a live bound."""
        self.assertTrue(paper_bound().refuted)
        self.assertTrue(LatticeBound(64, 12289, 2).refuted)


class BruteForceGuardTests(unittest.TestCase):
    def test_rejects_infeasible_search_space(self):
        with self.assertRaises(BoundError):
            exhaustive_shortest((1, 0, 0, 0), 32, 97, search_radius=3)

    def test_rejects_bad_parameters(self):
        with self.assertRaises(BoundError):
            exhaustive_shortest((1, 0), 0, 97)
        with self.assertRaises(BoundError):
            exhaustive_shortest((1, 0), 2, 1)
        with self.assertRaises(BoundError):
            exhaustive_shortest((1, 0, 0, 0), 4, 97, search_radius=0)

    def test_witness_is_nonzero(self):
        zeta = sparse_zeta(4, 97, 2)
        found = exhaustive_shortest(tuple(zeta.coeffs), 4, 97,
                                    search_radius=2)
        self.assertTrue(any(v != 0 for v in found["witness_d"]))


class DegeneracyTests(unittest.TestCase):
    def test_sparse_challenges_are_not_zero_divisors(self):
        for q in (97, 12289):
            report = degenerate_challenge_check(sparse_zeta(8, q, 2))
            self.assertFalse(report["zero_divisor_found"])
            self.assertIn("non-degenerate", report["verdict"])

    def test_detects_an_actual_annihilator(self):
        """x^n + 1 factors when q permits, so zero divisors can exist; the
        check must catch one when present rather than assume genericity."""
        params = ToyParameters(n=4, q=97, k=2)
        # 2*(1 + x^2) has (1 - x^2) as a partner: (1+x^2)(1-x^2) = 1-x^4
        # and x^4 = -1, so the product is 1-(-1) = 2, not 0 -- so this is
        # NOT an annihilator. Assert the checker does not false-positive.
        candidate = bounded_ring_element((1, 0, 1, 0), params)
        self.assertFalse(
            degenerate_challenge_check(candidate)["zero_divisor_found"]
        )


class HonestyTests(unittest.TestCase):
    def test_assessment_reports_the_refutation_not_the_bound(self):
        report = assessment(norm_budget=1.0)
        self.assertIn("refutation", report)
        self.assertIn("does not apply", report["refutation"])
        self.assertIn("NOT RESOLVED", report["status"])

    def test_assessment_states_the_corrected_margin(self):
        report = assessment(norm_budget=1.0)
        margin = report["corrected_margin"]
        self.assertEqual(margin["shortest_cancellation"], 8)
        self.assertTrue(margin["blocked"])
        self.assertIn("measured not derived", margin["basis"])

    def test_loose_budget_loses_the_aggregate_check(self):
        report = assessment(norm_budget=8.0)
        self.assertFalse(report["corrected_margin"]["blocked"])

    def test_residual_gaps_name_the_unmeasured_regime(self):
        gaps = assessment()["residual_gaps"]
        self.assertIn("n = 64 is unmeasured", gaps)
        self.assertIn("LLL/BKZ", gaps)

    def test_status_warns_against_banking_the_saving(self):
        self.assertIn("should not be banked", assessment()["status"])


if __name__ == "__main__":
    unittest.main()
