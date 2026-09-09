"""Tests for M-LWE hiding hardness.

Pins the dual-attack reduction, the sample-limit handling (the subtle part),
and the cross-check that M-LWE and M-SIS land at comparable strength -- which
is the paper's stated design goal (m ~ 2n balances the two).
"""

import math
import unittest
from decimal import Decimal

from pqct.mlwe_hardness import (
    PAPER_DELTA,
    achievable_length_log2_at,
    analyze_mlwe,
    distinguishing_beta,
    optimal_samples,
    paper_mlwe_report,
    uniform_ternary_sigma,
)
from pqct.msis_hardness import HardnessError, analyze_msis
from pqct.paper_bounds import gamma_bin_reduced

Q_PAPER = 2 ** 49 - 2 ** 18 + 2 ** 9 + 1


class ErrorDistributionTests(unittest.TestCase):
    def test_ternary_sigma_is_sqrt_two_thirds(self):
        self.assertAlmostEqual(uniform_ternary_sigma(1), math.sqrt(2.0 / 3.0), places=12)

    def test_sigma_grows_with_bound(self):
        self.assertLess(uniform_ternary_sigma(1), uniform_ternary_sigma(2))
        self.assertAlmostEqual(uniform_ternary_sigma(2), math.sqrt(2.0), places=12)

    def test_rejects_zero_bound(self):
        with self.assertRaises(HardnessError):
            uniform_ternary_sigma(0)

    def test_distinguishing_beta_is_q_over_sigma(self):
        self.assertAlmostEqual(distinguishing_beta(1000, 2.0), 500.0, places=9)
        with self.assertRaises(HardnessError):
            distinguishing_beta(1, 1.0)
        with self.assertRaises(HardnessError):
            distinguishing_beta(1000, 0.0)


class DualLatticeTests(unittest.TestCase):
    def test_optimal_samples_minimises_the_length(self):
        n_int, log2_q = 1984, 49.0
        log2_delta = math.log2(PAPER_DELTA)
        best = optimal_samples(n_int, log2_q, log2_delta)
        at_best = achievable_length_log2_at(n_int, log2_q, log2_delta, int(best))
        for factor in (0.5, 0.8, 0.95, 1.05, 1.25, 2.0):
            other = achievable_length_log2_at(
                n_int, log2_q, log2_delta, max(1, int(best * factor))
            )
            self.assertLessEqual(at_best, other + 0.01)

    def test_optimum_value_equals_the_eq2_exponential_form(self):
        n_int, log2_q = 1984, 49.0
        log2_delta = math.log2(PAPER_DELTA)
        best = optimal_samples(n_int, log2_q, log2_delta)
        direct = achievable_length_log2_at(n_int, log2_q, log2_delta, best)
        closed = 2.0 * math.sqrt(n_int * log2_q * log2_delta)
        self.assertAlmostEqual(direct, closed, places=6)

    def test_off_optimum_length_is_longer(self):
        """Forcing fewer samples than optimal makes the attack WEAKER."""
        n_int, log2_q = 1984, 49.0
        log2_delta = math.log2(PAPER_DELTA)
        best = int(optimal_samples(n_int, log2_q, log2_delta))
        self.assertGreater(
            achievable_length_log2_at(n_int, log2_q, log2_delta, best - 500),
            achievable_length_log2_at(n_int, log2_q, log2_delta, best),
        )

    def test_rejects_bad_sample_counts(self):
        with self.assertRaises(HardnessError):
            achievable_length_log2_at(1984, 49.0, 0.006, 0)
        with self.assertRaises(HardnessError):
            optimal_samples(1984, 49.0, 0.0)


class PaperProfileTests(unittest.TestCase):
    def setUp(self):
        self.report = paper_mlwe_report()

    def test_secret_dimension_is_m_minus_n_times_d(self):
        """Lemma 1: M-LWE(m-n, m, q, B) => (60-29)*64 = 1984."""
        self.assertEqual(self.report.n_int, (60 - 29) * 64)
        self.assertEqual(self.report.available_samples, 60 * 64)

    def test_criterion_holds_at_the_paper_delta(self):
        self.assertTrue(self.report.criterion_holds_at_paper_delta)

    def test_sample_limit_is_detected(self):
        """The optimum wants more columns than the HMC exposes, so the
        attacker is forced off-optimum. Missing this would UNDERSTATE
        security."""
        self.assertTrue(self.report.samples_are_limiting)
        self.assertGreater(self.report.optimal_samples, self.report.available_samples)
        self.assertTrue(
            any("SAMPLE-LIMITED" in note for note in self.report.notes)
        )

    def test_bits_are_in_the_plausible_lattice_range(self):
        self.assertGreater(self.report.min_cost_bits, 80.0)
        self.assertLess(self.report.max_cost_bits, 130.0)
        self.assertLess(
            self.report.costs_bits["ADPS16_quantum"],
            self.report.costs_bits["ADPS16_classical"],
        )

    def test_blocksize_in_asymptotic_regime(self):
        self.assertGreater(self.report.required_blocksize, 50)

    def test_notes_disclose_the_model_choice_and_ternary_caveat(self):
        joined = " ".join(self.report.notes)
        self.assertIn("MODEL CHOICE", joined)
        self.assertIn("hybrid", joined)

    def test_beta_is_the_distinguishing_threshold_not_a_norm_bound(self):
        """beta = q/sigma_e; documents that this differs from M-SIS's beta."""
        expected = math.log2(Q_PAPER / math.sqrt(2.0 / 3.0))
        self.assertAlmostEqual(self.report.log2_beta, expected, places=6)


class BalanceWithMSISTests(unittest.TestCase):
    """The paper picks m ~ 2n to BALANCE M-SIS and M-LWE. Check it worked."""

    def test_mlwe_and_msis_are_comparable_strength(self):
        mlwe = paper_mlwe_report()
        gb = gamma_bin_reduced(8, 64, 56, 64, 2, Decimal(15), Decimal(15), 1, 60)
        msis = analyze_msis(
            n_module=29, d=64, q=Q_PAPER, beta=float(2 * gb)
        )
        # Within ~10 bits of each other is "balanced" for this purpose.
        self.assertLess(
            abs(mlwe.min_cost_bits - msis.min_cost_bits), 10.0,
            f"M-LWE {mlwe.min_cost_bits:.1f} vs M-SIS {msis.min_cost_bits:.1f} "
            "-- the m~2n balancing claim would be wrong",
        )

    def test_neither_problem_reaches_128_bits(self):
        """Both land below the paper's claimed level under modern models --
        same root cause as documented in docs/MSIS_HARDNESS.md."""
        mlwe = paper_mlwe_report()
        self.assertLess(mlwe.min_cost_bits, 128.0)

    def test_mlwe_security_grows_with_m_minus_n(self):
        """The paper's stated monotonicity: security rises with m-n."""
        low = analyze_mlwe(secret_rank=10, samples_rank=60, d=64, q=Q_PAPER)
        high = analyze_mlwe(secret_rank=31, samples_rank=60, d=64, q=Q_PAPER)
        self.assertGreater(high.min_cost_bits, low.min_cost_bits)

    def test_rejects_inconsistent_ranks(self):
        with self.assertRaises(HardnessError):
            analyze_mlwe(secret_rank=61, samples_rank=60, d=64, q=Q_PAPER)
        with self.assertRaises(HardnessError):
            analyze_mlwe(secret_rank=0, samples_rank=60, d=64, q=Q_PAPER)


if __name__ == "__main__":
    unittest.main()
