"""Tests for the zeta-cancellation attack on non-adaptive zeta.

These pin a NARROWING, not a security proof. The valuable content is the
reframing: cancellations always exist for known zeta, so the aggregate
check's soundness reduces entirely to whether a cancellation fits the
verifier's norm budget.
"""

from __future__ import annotations

import unittest

from pqct.challenge import sample_sparse_challenge
from pqct.hmc import bounded_ring_element, centered_coefficients
from pqct.ring_challenge import challenge_ring_element
from pqct.ring_commitment import RingElement, ToyParameters
from pqct.zeta_cancellation import (
    CancellationError,
    assessment,
    norm_inflation_factor,
    trivial_cancellation,
)


class CancellationExistenceTests(unittest.TestCase):
    """The reframing: existence is trivial, so norms are the whole story."""

    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=5)
        self.zeta = challenge_ring_element(
            sample_sparse_challenge(b"zeta-attack", self.params, 4, 8)
        )

    def test_cancellation_always_exists_for_known_zeta(self):
        """d_0 = -zeta*d_1 cancels by construction, so 'can they cancel?'
        is the wrong question."""
        result = trivial_cancellation(self.zeta, accounts=2)
        self.assertTrue(result.found)

    def test_forced_deviation_is_nonzero(self):
        """A zero solution would prove nothing."""
        result = trivial_cancellation(self.zeta, accounts=2)
        self.assertTrue(
            any(any(c != 0 for c in d.coeffs) for d in result.deviations)
        )

    def test_cancellation_exceeds_a_tight_norm_budget(self):
        """The substantive finding: the cheapest cancellation is inflated by
        the challenge's peak coefficient (8 here) and so fails a budget of
        1. The norm gate, not the randomness of zeta, is what blocks it."""
        result = trivial_cancellation(self.zeta, accounts=2, norm_budget=1)
        self.assertEqual(result.max_coefficient, 8)
        self.assertFalse(result.within_budget)
        self.assertFalse(result.exploitable)

    def test_a_loose_budget_would_make_it_exploitable(self):
        """Shows the finding is budget-dependent, not absolute -- a design
        with a generous norm budget WOULD lose the aggregate check."""
        result = trivial_cancellation(self.zeta, accounts=2, norm_budget=64)
        self.assertTrue(result.within_budget)
        self.assertTrue(result.exploitable)
        self.assertIn("NO SOUNDNESS", result.summary()["verdict"])

    def test_more_accounts_still_cancels(self):
        result = trivial_cancellation(self.zeta, accounts=4)
        self.assertTrue(result.found)
        self.assertEqual(result.accounts, 4)

    def test_single_account_rejected(self):
        with self.assertRaises(CancellationError):
            trivial_cancellation(self.zeta, accounts=1)


class InflationTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=5)

    def test_inflation_equals_challenge_peak(self):
        """Multiplying a unit deviation by a sparse challenge inflates the
        infinity norm to the challenge's peak coefficient."""
        for peak in (2, 4, 8):
            zeta = challenge_ring_element(
                sample_sparse_challenge(b"peak", self.params, 4, peak)
            )
            report = norm_inflation_factor(zeta)
            self.assertEqual(report["zeta_peak_coefficient"], peak)
            self.assertEqual(report["product_infinity_norm"], peak)

    def test_sparsity_is_reported(self):
        zeta = challenge_ring_element(
            sample_sparse_challenge(b"sparse", self.params, 4, 8)
        )
        self.assertEqual(norm_inflation_factor(zeta)["zeta_nonzero_coefficients"], 4)

    def test_identity_challenge_does_not_inflate(self):
        """Sanity check on the measurement itself: multiplying by 1 must
        leave the norm alone."""
        one = bounded_ring_element((1,) + (0,) * 7, self.params)
        report = norm_inflation_factor(one)
        self.assertEqual(report["product_infinity_norm"], 1)


class HonestyTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=5)
        self.zeta = challenge_ring_element(
            sample_sparse_challenge(b"honest", self.params, 4, 8)
        )

    def test_assessment_states_the_residual_gap(self):
        """This narrows the question; it does not answer it. The module must
        say so, and must cross-reference the follow-up that refuted the
        sqrt(q) bound so the two modules cannot be read as agreeing for the
        same reason."""
        report = assessment(self.zeta, norm_budget=1)
        self.assertEqual(report["status"], "NARROWED, not closed")
        gap = report["residual_gap"]
        self.assertIn("SUPERSEDED IN PART", gap)
        self.assertIn("cancellation_bound", gap)
        self.assertIn("REFUTED", gap)
        self.assertIn("LLL/BKZ", gap)
        self.assertIn("should not", gap.replace("Do not", "should not"))

    def test_negative_result_is_not_called_security(self):
        result = trivial_cancellation(self.zeta, accounts=2, norm_budget=1)
        self.assertIn("NOT a proof", result.summary()["verdict"])


if __name__ == "__main__":
    unittest.main()
