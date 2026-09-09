"""Tests for the M-SIS delta-criterion hardness analysis.

These pin (a) the BKZ root-Hermite formula against published anchors,
(b) Eq.(2) behaviour on the paper profile, and (c) the resolution of the
Gaussian-heuristic paradox: hardness is governed by the OPTIMAL
sub-dimension, not the full column count.
"""

import math
import unittest
from decimal import Decimal

from pqct.msis_hardness import (
    HardnessError,
    PAPER_DELTA,
    achievable_length_log2,
    analyze_msis,
    blocksize_for_root_hermite,
    optimal_sublattice_dimension,
    required_root_hermite,
    root_hermite_from_blocksize,
)
from pqct.paper_bounds import gamma_bin_reduced

Q_PAPER = 2 ** 49 - 2 ** 18 + 2 ** 9 + 1


def paper_gamma_bin(S=2):
    return gamma_bin_reduced(8, 64, 56, 64, S, Decimal(15), Decimal(15), 1, 60)


class RootHermiteTests(unittest.TestCase):
    def test_monotone_decreasing_in_blocksize(self):
        previous = None
        for k in (50, 100, 200, 345, 500, 1000, 2000):
            delta = root_hermite_from_blocksize(k)
            self.assertGreater(delta, 1.0)
            if previous is not None:
                self.assertLess(delta, previous, "delta must fall as k grows")
            previous = delta

    def test_matches_published_anchors(self):
        """Standard BKZ tables: delta 1.005 ~ k 286, 1.0045 ~ k 335,
        1.003 ~ k 596. Tolerance is loose because published tables vary
        by simulator, but the SCALE must be right (hundreds, not thousands)."""
        self.assertAlmostEqual(blocksize_for_root_hermite(1.005), 286, delta=15)
        self.assertAlmostEqual(blocksize_for_root_hermite(1.0045), 335, delta=15)
        self.assertAlmostEqual(blocksize_for_root_hermite(1.003), 596, delta=25)

    def test_inversion_round_trips_exactly(self):
        for target in (1.0045, 1.004, 1.003, 1.006, 1.01):
            k = blocksize_for_root_hermite(target)
            self.assertAlmostEqual(root_hermite_from_blocksize(k), target, places=12)

    def test_rejects_nonphysical_inputs(self):
        with self.assertRaises(HardnessError):
            root_hermite_from_blocksize(1)
        with self.assertRaises(HardnessError):
            blocksize_for_root_hermite(1.0)
        with self.assertRaises(HardnessError):
            blocksize_for_root_hermite(0.5)

    def test_unreachable_delta_raises(self):
        """A delta too close to 1 is not reachable by any bounded block size."""
        with self.assertRaises(HardnessError):
            blocksize_for_root_hermite(1.0 + 1e-12, hi=1000.0)


class Equation2Tests(unittest.TestCase):
    def test_optimal_dimension_minimises_the_length(self):
        """m' = sqrt(n*log2 q/log2 delta) must actually minimise
        delta^m' * q^(n/m'), i.e. Eq.(2)'s exponential is a real optimum."""
        n_int, log2_q = 1856, 49.0
        log2_delta = math.log2(1.0045)
        best = optimal_sublattice_dimension(n_int, log2_q, log2_delta)

        def length_log2(m_prime):
            return m_prime * log2_delta + log2_q * n_int / m_prime

        at_best = length_log2(best)
        for factor in (0.5, 0.8, 0.95, 1.05, 1.25, 2.0):
            self.assertLessEqual(
                at_best, length_log2(best * factor) + 1e-9,
                f"m'*{factor} beat the claimed optimum",
            )

    def test_optimum_value_equals_eq2_exponential(self):
        """At m', the length is exactly 2*sqrt(n*log2 q*log2 delta)."""
        n_int, log2_q = 1856, 49.0
        log2_delta = math.log2(1.0045)
        best = optimal_sublattice_dimension(n_int, log2_q, log2_delta)
        direct = best * log2_delta + log2_q * n_int / best
        self.assertAlmostEqual(
            direct, achievable_length_log2(n_int, log2_q, log2_delta), places=6
        )

    def test_required_delta_inverts_the_exponential(self):
        n_int, log2_q = 1856, 49.0
        for log2_beta in (30.0, 48.02, 48.5):
            delta = required_root_hermite(log2_beta, n_int, log2_q)
            self.assertAlmostEqual(
                achievable_length_log2(n_int, log2_q, math.log2(delta)),
                log2_beta, places=6,
            )

    def test_smaller_beta_needs_stronger_reduction(self):
        """Reaching a SHORTER vector requires a smaller delta (harder)."""
        n_int, log2_q = 1856, 49.0
        strong = required_root_hermite(30.0, n_int, log2_q)
        weak = required_root_hermite(48.0, n_int, log2_q)
        self.assertLess(strong, weak)


class PaperProfileTests(unittest.TestCase):
    def setUp(self):
        self.beta = float(2 * paper_gamma_bin(2))  # two openings differ by <= 2*gamma
        self.report = analyze_msis(
            n_module=29, d=64, q=Q_PAPER, beta=self.beta
        )

    def test_beta_below_q(self):
        self.assertTrue(self.report.beta_lt_q)
        self.assertAlmostEqual(self.report.log2_beta, 48.02, places=1)

    def test_eq2_holds_for_the_paper_profile(self):
        """The paper's OWN criterion is satisfied -- but tightly."""
        self.assertTrue(self.report.eq2_holds_at_paper_delta)
        margin = self.report.eq2_rhs_log2_at_paper_delta - self.report.log2_beta
        self.assertGreater(margin, 0.0)
        self.assertLess(margin, 2.0, "margin is under 4x; record it as tight")

    def test_required_delta_agrees_with_lattice_estimator(self):
        """Independent cross-check: the real lattice-estimator reported
        delta = 1.0042178 for this profile; the Eq.(2) inversion here needs
        1.00440. Two unrelated code paths within 3e-4."""
        self.assertAlmostEqual(self.report.required_delta, 1.00440, places=4)
        self.assertAlmostEqual(self.report.required_delta, 1.0042178, delta=3e-4)

    def test_optimal_dimension_matches_estimator_reported_d(self):
        """lattice-estimator reported d in 3378..4008 for this instance;
        the analytic optimum lands inside that band. This is the evidence
        that the FULL column count (7936) was the wrong dimension."""
        self.assertGreater(self.report.optimal_dimension, 3378)
        self.assertLess(self.report.optimal_dimension, 4008)

    def test_cost_models_land_below_128_bits(self):
        """Modern core-SVP models give ~91-118 bits, NOT the paper's 128.
        This is the substantive finding: Eq.(2) holding is not 128-bit
        security under a modern delta->bits mapping."""
        costs = self.report.costs_bits
        values = [v for v in costs.values() if v is not None]
        self.assertTrue(values)
        self.assertLess(max(values), 128.0)
        self.assertGreater(min(values), 60.0)
        self.assertLess(costs["ADPS16_quantum"], costs["ADPS16_classical"])

    def test_notes_disclose_the_model_choice(self):
        joined = " ".join(self.report.notes)
        self.assertIn("MODEL CHOICE", joined)
        self.assertIn("Gaussian-heuristic", joined)

    def test_blocksize_in_asymptotic_regime(self):
        self.assertGreater(self.report.required_blocksize, 50)

    def test_beta_above_q_is_flagged(self):
        report = analyze_msis(
            n_module=29, d=64, q=Q_PAPER, beta=float(Q_PAPER) * 2
        )
        self.assertFalse(report.beta_lt_q)
        self.assertTrue(any("beta >= q" in note for note in report.notes))

    def test_rejects_bad_inputs(self):
        with self.assertRaises(HardnessError):
            analyze_msis(n_module=0, d=64, q=Q_PAPER, beta=1.0)
        with self.assertRaises(HardnessError):
            analyze_msis(n_module=29, d=64, q=Q_PAPER, beta=0.0)


if __name__ == "__main__":
    unittest.main()
