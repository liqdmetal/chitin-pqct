"""Tests for the finite-support Gaussian truncation distance.

Two things get pinned: the EXACT identity SD = tail/S_inf (checked against
the definition of statistical distance computed by brute force), and the
soundness of the closed-form erfc bound (it must never sit below the exact
value, or a "certified" bound would be a lie).
"""

import math
import unittest
from decimal import Decimal

from pqct.protocol1_sampling import FiniteDiscreteGaussian
from pqct.truncation_distance import (
    DistanceError,
    closed_form_bound,
    exact_statistical_distance,
    profile_distance,
    required_tail_for_target,
    sigmas_of_tail,
    transcript_distance,
)


def brute_force_statistical_distance(sigma: float, tail: int,
                                     reach: int = 400) -> float:
    """SD from its DEFINITION: half the L1 distance between the two laws."""
    rho = lambda x: math.exp(-(x * x) / (2.0 * sigma * sigma))
    inside = sum(rho(x) for x in range(-tail, tail + 1))
    outside = 2.0 * sum(rho(x) for x in range(tail + 1, tail + 1 + reach))
    total = inside + outside
    half_l1 = 0.5 * (
        sum(abs(rho(x) / inside - rho(x) / total) for x in range(-tail, tail + 1))
        + 2.0 * sum(rho(x) / total for x in range(tail + 1, tail + 1 + reach))
    )
    return half_l1


class ExactDistanceTests(unittest.TestCase):
    def test_matches_the_definition_of_statistical_distance(self):
        """The tail/S_inf identity must equal the brute-force L1/2."""
        for sigma, tail in ((1, 3), (2, 6), (2, 10), (4, 12), (8, 20)):
            with self.subTest(sigma=sigma, tail=tail):
                profile = FiniteDiscreteGaussian(Decimal(sigma), tail)
                self.assertAlmostEqual(
                    exact_statistical_distance(profile),
                    brute_force_statistical_distance(float(sigma), tail),
                    places=12,
                )

    def test_distance_falls_as_the_tail_grows(self):
        previous = None
        for tail in (2, 4, 6, 8, 10, 12):
            value = exact_statistical_distance(
                FiniteDiscreteGaussian(Decimal(2), tail)
            )
            if previous is not None:
                self.assertLess(value, previous)
            previous = value

    def test_distance_is_a_probability(self):
        for sigma, tail in ((1, 0), (1, 1), (3, 9), (15, 60)):
            value = exact_statistical_distance(
                FiniteDiscreteGaussian(Decimal(sigma), tail)
            )
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.0)

    def test_depends_only_on_the_ratio_for_the_bound(self):
        """erfc(T/(sigma*sqrt2)) is a function of T/sigma alone."""
        self.assertAlmostEqual(
            closed_form_bound(1.0, 4), closed_form_bound(10.0, 40), places=15
        )
        self.assertAlmostEqual(
            closed_form_bound(2.0, 16), closed_form_bound(8.0, 64), places=15
        )

    def test_rejects_bad_inputs(self):
        with self.assertRaises(DistanceError):
            closed_form_bound(0.0, 4)
        with self.assertRaises(DistanceError):
            closed_form_bound(1.0, -1)
        with self.assertRaises(DistanceError):
            sigmas_of_tail(0.0, 4)


class BoundSoundnessTests(unittest.TestCase):
    def test_bound_never_falls_below_the_exact_value(self):
        """A bound that undershoots is worse than no bound at all."""
        cases = (
            (1, 4), (1, 6), (1, 8), (2, 8), (2, 16), (4, 20),
            (8, 40), (8, 92), (15, 60), (15, 173), (3, 7), (5, 30),
        )
        for sigma, tail in cases:
            with self.subTest(sigma=sigma, tail=tail):
                profile = FiniteDiscreteGaussian(Decimal(sigma), tail)
                exact = exact_statistical_distance(profile)
                bound = closed_form_bound(float(sigma), tail)
                self.assertGreaterEqual(bound, exact)

    def test_bound_is_not_absurdly_loose(self):
        """Within ~2 orders of magnitude keeps it useful, not just true."""
        for sigma, tail in ((2, 8), (8, 40), (15, 60)):
            profile = FiniteDiscreteGaussian(Decimal(sigma), tail)
            exact = exact_statistical_distance(profile)
            bound = closed_form_bound(float(sigma), tail)
            self.assertLess(bound, exact * 1000.0)

    def test_eleven_and_a_half_sigmas_reaches_2_to_the_minus_100(self):
        """The rule of thumb the module claims: T ~ 11.5*sigma buys 2^-100."""
        bound = closed_form_bound(1.0, 12)
        self.assertLess(bound, 2.0 ** -100)


class CompositionTests(unittest.TestCase):
    def test_composition_scales_with_coordinate_count(self):
        profile = FiniteDiscreteGaussian(Decimal(2), 12)
        one = profile_distance("p", profile, 1)
        many = profile_distance("p", profile, 500)
        self.assertAlmostEqual(
            many.composed_bound, 500 * one.bound_per_coordinate, places=15
        )

    def test_composition_is_capped_at_one(self):
        profile = FiniteDiscreteGaussian(Decimal(2), 2)
        huge = profile_distance("p", profile, 10 ** 9)
        self.assertLessEqual(huge.composed_bound, 1.0)

    def test_transcript_bound_sums_profiles(self):
        p1 = FiniteDiscreteGaussian(Decimal(2), 20)
        p2 = FiniteDiscreteGaussian(Decimal(8), 60)
        report = transcript_distance(
            (("t_profile", p1, 64), ("opening_profile", p2, 128))
        )
        expected = (
            64 * closed_form_bound(2.0, 20) + 128 * closed_form_bound(8.0, 60)
        )
        self.assertAlmostEqual(report.total_bound, expected, places=15)
        self.assertTrue(all(p.bound_is_sound for p in report.profiles))

    def test_transcript_meets_target_with_wide_tails(self):
        p1 = FiniteDiscreteGaussian(Decimal(2), 40)
        p2 = FiniteDiscreteGaussian(Decimal(8), 160)
        report = transcript_distance(
            (("t", p1, 64), ("open", p2, 128)), target=2.0 ** -100
        )
        self.assertTrue(report.meets_target, report.summary())
        self.assertLess(report.log2_total_bound, -100.0)

    def test_transcript_fails_target_with_narrow_tails(self):
        p1 = FiniteDiscreteGaussian(Decimal(2), 6)
        report = transcript_distance((("t", p1, 64),), target=2.0 ** -100)
        self.assertFalse(report.meets_target)

    def test_no_profiles_is_refused(self):
        with self.assertRaises(DistanceError):
            transcript_distance(())


class RequiredTailTests(unittest.TestCase):
    def test_required_tail_actually_achieves_the_target(self):
        for sigma, coordinates in ((1.0, 1), (2.0, 64), (8.0, 512), (15.0, 3904)):
            with self.subTest(sigma=sigma, coordinates=coordinates):
                tail = required_tail_for_target(sigma, coordinates)
                achieved = coordinates * closed_form_bound(sigma, tail)
                self.assertLessEqual(achieved, 2.0 ** -100)

    def test_required_tail_is_minimal(self):
        """One less must FAIL, or the search is not returning the minimum."""
        for sigma, coordinates in ((2.0, 64), (8.0, 512)):
            tail = required_tail_for_target(sigma, coordinates)
            self.assertGreater(
                coordinates * closed_form_bound(sigma, tail - 1), 2.0 ** -100
            )

    def test_required_tail_grows_with_sigma_and_coordinates(self):
        base = required_tail_for_target(2.0, 64)
        self.assertGreater(required_tail_for_target(8.0, 64), base)
        self.assertGreaterEqual(required_tail_for_target(2.0, 100_000), base)

    def test_rejects_bad_inputs(self):
        with self.assertRaises(DistanceError):
            required_tail_for_target(0.0, 10)
        with self.assertRaises(DistanceError):
            required_tail_for_target(2.0, 0)
        with self.assertRaises(DistanceError):
            required_tail_for_target(2.0, 10, target=0.0)
        with self.assertRaises(DistanceError):
            required_tail_for_target(2.0, 10, target=1.0)


if __name__ == "__main__":
    unittest.main()
