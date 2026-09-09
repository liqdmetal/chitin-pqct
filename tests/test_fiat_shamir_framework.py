"""Tests for the Fiat-Shamir framework.

These pin the arithmetic and, more importantly, pin the HONESTY properties:
the framework must report OPEN while obligations are undischarged, and must
never present residual_bits_optimistic as a security level.
"""

import math
import unittest

from pqct.fiat_shamir_framework import (
    OBLIGATIONS,
    FiatShamirFramework,
    FrameworkError,
    Status,
    challenge_space_size,
    forking_loss_bits,
    paper_framework,
    qrom_reprogramming_loss_bits,
    soundness_error_bits,
)


class ChallengeSpaceTests(unittest.TestCase):
    def test_matches_the_combinatorial_formula(self):
        self.assertEqual(
            challenge_space_size(56, 8, 64),
            math.comb(64, 56) * 16 ** 56,
        )

    def test_paper_parameters_give_about_256_bits(self):
        self.assertAlmostEqual(soundness_error_bits(56, 8, 64), 256.04, places=1)

    def test_grows_with_weight_and_bound(self):
        base = challenge_space_size(8, 2, 64)
        self.assertGreater(challenge_space_size(16, 2, 64), base)
        self.assertGreater(challenge_space_size(8, 4, 64), base)

    def test_rejects_impossible_parameters(self):
        with self.assertRaises(FrameworkError):
            challenge_space_size(0, 8, 64)
        with self.assertRaises(FrameworkError):
            challenge_space_size(56, 0, 64)
        with self.assertRaises(FrameworkError):
            challenge_space_size(65, 8, 64)  # weight > degree


class LossTests(unittest.TestCase):
    def test_forking_loss_scales_with_transcript_count(self):
        self.assertAlmostEqual(forking_loss_bits(2 ** 64, 2), 64.0, places=6)
        self.assertAlmostEqual(forking_loss_bits(2 ** 64, 3), 128.0, places=6)
        self.assertAlmostEqual(forking_loss_bits(2 ** 64, 4), 192.0, places=6)

    def test_qrom_loss_is_two_log_q(self):
        self.assertAlmostEqual(qrom_reprogramming_loss_bits(2 ** 64), 128.0, places=6)

    def test_rejects_bad_query_counts(self):
        with self.assertRaises(FrameworkError):
            forking_loss_bits(0)
        with self.assertRaises(FrameworkError):
            qrom_reprogramming_loss_bits(0)
        with self.assertRaises(FrameworkError):
            forking_loss_bits(2 ** 64, transcripts=1)


class ResidualBudgetTests(unittest.TestCase):
    """The substantive finding: the optimistic margin vanishes at Q=2^64."""

    def test_residual_is_deeply_negative_at_2_to_the_64(self):
        """CORRECTED. An earlier version asserted ~0 bits here, which was
        computed for a three-move protocol. The implemented protocol has two
        Fiat-Shamir challenges (zeta then x), so extraction needs a 6-leaf
        tree and QROM loss compounds per round: 256 - 320 - 256 = -320."""
        framework = paper_framework(quantum_queries=2 ** 64)
        self.assertAlmostEqual(
            framework.residual_bits_optimistic, -320.0, delta=1.0
        )
        self.assertAlmostEqual(framework.forking_loss, 320.0, delta=1.0)
        self.assertAlmostEqual(framework.qrom_loss, 256.0, delta=1.0)

    def test_residual_is_negative_even_for_small_query_budgets(self):
        """The multi-round losses (5+4)*log2(Q) = 9*log2(Q) outrun the 256
        bits of soundness once log2(Q) > ~28, so there is no comfortable
        regime under the corrected structure."""
        self.assertLess(
            paper_framework(quantum_queries=2 ** 32).residual_bits_optimistic, 0.0
        )
        # Only a very small query budget leaves anything at all.
        self.assertGreater(
            paper_framework(quantum_queries=2 ** 16).residual_bits_optimistic, 0.0
        )

    def test_reducing_to_one_round_recovers_320_bits(self):
        """What the non-adaptive zeta attempt would buy, if sound."""
        two_round = paper_framework(quantum_queries=2 ** 64)
        one_round = FiatShamirFramework(
            56, 8, 64, 2 ** 64, transcripts_needed=3, challenge_rounds=1
        )
        self.assertAlmostEqual(
            one_round.residual_bits_optimistic
            - two_round.residual_bits_optimistic,
            320.0, delta=1.0,
        )

    def test_needing_fewer_transcripts_recovers_margin(self):
        """Documents WHERE the margin goes: (t-1)*log2(Q) of forking loss."""
        three = FiatShamirFramework(56, 8, 64, 2 ** 64, transcripts_needed=3)
        two = FiatShamirFramework(56, 8, 64, 2 ** 64, transcripts_needed=2)
        self.assertGreater(
            two.residual_bits_optimistic, three.residual_bits_optimistic + 60
        )


class HonestyTests(unittest.TestCase):
    """A framework that overstates its own status is worse than none."""

    def test_status_is_open_while_obligations_are_undischarged(self):
        framework = paper_framework()
        self.assertTrue(framework.open_obligations)
        self.assertIn("OPEN", framework.overall_status)
        self.assertIn("no Fiat-Shamir security claim", framework.overall_status)

    def test_four_obligations_are_open_and_named(self):
        framework = paper_framework()
        open_names = {o.name for o in framework.open_obligations}
        self.assertIn("classical-rewinding-to-3-transcripts", open_names)
        self.assertIn("quantum-rewinding-obstruction", open_names)
        self.assertIn("commitment-binding-under-relaxation", open_names)
        self.assertIn("transcript-simulation-shvzk", open_names)

    def test_quantum_rewinding_is_explicitly_not_attempted(self):
        obligation = next(
            o for o in OBLIGATIONS if o.name == "quantum-rewinding-obstruction"
        )
        self.assertEqual(obligation.status, Status.NOT_ATTEMPTED)
        self.assertFalse(obligation.discharged)

    def test_code_evidenced_obligations_cite_real_modules(self):
        for obligation in OBLIGATIONS:
            if obligation.status is Status.CODE_EVIDENCED:
                with self.subTest(name=obligation.name):
                    self.assertIn("pqct/", obligation.evidence)

    def test_summary_carries_the_warning(self):
        summary = paper_framework().summary()
        self.assertIn("FRAMEWORK, not a proof", summary["warning"])
        self.assertIn("NOT a security level", summary["overall_status"])

    def test_discharged_and_open_partition_the_obligations(self):
        framework = paper_framework()
        self.assertEqual(
            len(framework.discharged_obligations) + len(framework.open_obligations),
            len(OBLIGATIONS),
        )

    def test_no_obligation_claims_a_proof(self):
        """Guard against drift: nothing here may claim to have proven FS."""
        for obligation in OBLIGATIONS:
            lowered = obligation.evidence.lower()
            self.assertNotIn("proves fiat-shamir", lowered)
            self.assertNotIn("proof of fiat-shamir", lowered)


if __name__ == "__main__":
    unittest.main()
