"""Tests for the zeta grinding analysis.

The structural claim is the one worth pinning: the sparse sampler emits
exactly +-p, so NO zeta in its range has a smaller peak, and grinding
cannot lower the cancellation margin no matter how many statements the
adversary tries. The empirical run confirms it; these tests make sure the
sampler keeps that property and the report stays honest.
"""

import unittest

from pqct.zeta_grinding import (
    CHALLENGE_PEAK,
    CHALLENGE_WEIGHT,
    GrindingError,
    GrindingReport,
    effective_peak,
    is_zero_divisor_cheap,
    sample_challenge,
    simulate_grinding,
    structural_argument,
    weight_of,
)


class SamplerTests(unittest.TestCase):
    """The property everything rests on: every coefficient is exactly +-p."""

    def test_every_nonzero_coefficient_is_exactly_peak(self):
        for seed in range(64):
            zeta = sample_challenge(seed.to_bytes(8, "big"))
            for c in zeta:
                self.assertIn(abs(c), (0, CHALLENGE_PEAK))

    def test_weight_is_exact(self):
        for seed in range(64):
            zeta = sample_challenge(seed.to_bytes(8, "big"))
            self.assertEqual(weight_of(zeta), CHALLENGE_WEIGHT)

    def test_peak_is_never_below_nominal(self):
        """Grinding for a smaller peak is impossible: no such zeta exists."""
        for seed in range(256):
            zeta = sample_challenge(seed.to_bytes(8, "big"))
            self.assertEqual(effective_peak(zeta), CHALLENGE_PEAK)

    def test_deterministic(self):
        self.assertEqual(sample_challenge(b"x"), sample_challenge(b"x"))

    def test_different_seeds_differ(self):
        self.assertNotEqual(sample_challenge(b"a"), sample_challenge(b"b"))

    def test_invalid_weight_rejected(self):
        with self.assertRaises(GrindingError):
            sample_challenge(b"x", weight=0)
        with self.assertRaises(GrindingError):
            sample_challenge(b"x", weight=65)


class ZeroDivisorProbeTests(unittest.TestCase):
    def test_sampled_zetas_are_not_zero_divisors(self):
        for seed in range(16):
            zeta = sample_challenge(seed.to_bytes(8, "big"))
            self.assertFalse(is_zero_divisor_cheap(zeta))

    def test_probe_detects_the_zero_polynomial(self):
        """Sanity: the probe is not vacuously False."""
        zero = tuple([0] * 64)
        self.assertTrue(is_zero_divisor_cheap(zero))


class SimulationTests(unittest.TestCase):
    def test_no_favourable_zeta_in_sampling(self):
        report = simulate_grinding(128, zero_divisor_probe=False)
        self.assertEqual(report.minimum_peak_seen, CHALLENGE_PEAK)
        self.assertFalse(report.peak_ever_below_nominal)
        self.assertEqual(report.minimum_weight_seen, CHALLENGE_WEIGHT)

    def test_advantage_bound_scales_with_attempts(self):
        small = simulate_grinding(16, zero_divisor_probe=False)
        large = simulate_grinding(256, zero_divisor_probe=False)
        self.assertAlmostEqual(small.grinding_advantage_bound, -4.0)
        self.assertAlmostEqual(large.grinding_advantage_bound, -8.0)

    def test_attempts_must_be_positive(self):
        with self.assertRaises(GrindingError):
            simulate_grinding(0)

    def test_verdict_reports_no_favourable_zeta(self):
        report = simulate_grinding(32, zero_divisor_probe=False)
        self.assertIn("no favourable zeta", report.verdict)
        self.assertIn("exactly 8", report.verdict)


class HonestyTests(unittest.TestCase):
    def test_a_found_zero_divisor_removes_the_bound(self):
        """If grinding ever finds a degenerate zeta, the report must say
        BROKEN and refuse to claim any advantage bound."""
        report = GrindingReport(
            attempts=1000, minimum_peak_seen=8, nominal_peak=8,
            peak_ever_below_nominal=False, zero_divisors_found=1,
            minimum_weight_seen=56, nominal_weight=56,
        )
        self.assertEqual(report.grinding_advantage_bound, 0.0)
        self.assertIn("BROKEN", report.verdict)

    def test_a_smaller_peak_is_reported_as_weakened(self):
        report = GrindingReport(
            attempts=1000, minimum_peak_seen=4, nominal_peak=8,
            peak_ever_below_nominal=True, zero_divisors_found=0,
            minimum_weight_seen=56, nominal_weight=56,
        )
        self.assertEqual(report.grinding_advantage_bound, 0.0)
        self.assertIn("WEAKENED", report.verdict)

    def test_structural_argument_is_not_a_proof(self):
        argument = structural_argument()
        self.assertIn("NARROWED", argument["status"])
        self.assertIn("not proven absent", argument["status"])
        self.assertIn("cryptographer", argument["residual"])

    def test_structural_argument_states_what_grinding_can_still_do(self):
        """Honesty: grinding DOES control support and signs, and the
        argument must say so rather than claim total immunity."""
        argument = structural_argument()
        self.assertIn("SUPPORT", argument["what_grinding_can_still_do"])
        self.assertIn("SIGNS", argument["what_grinding_can_still_do"])


if __name__ == "__main__":
    unittest.main()
