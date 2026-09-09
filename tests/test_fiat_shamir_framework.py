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
    """The substantive finding, twice corrected.

    v1 asserted ~0 bits (computed for a 3-move protocol -- wrong structure).
    v2 asserted -320 bits (right structure, WRONG THEOREM: it applied the
       single-round forking lemma once per leaf of a 6-leaf tree).
    v3 (this) uses Attema-Fehr-Kloss 2022, which bounds the entire
       multi-round Fiat-Shamir transform by ONE factor (Q+1). The
       classical loss is log2(Q+1) ~ 64 bits, not 320. The conservative
       QROM figure is still large and is reported separately.
    """

    def test_forking_loss_is_log2_q_once(self):
        framework = paper_framework(quantum_queries=2 ** 64)
        self.assertAlmostEqual(framework.forking_loss, 64.0, delta=0.01)

    def test_total_loss_is_the_conservative_qrom_figure(self):
        """forking_loss + qrom_loss = full conservative QROM loss (260 at 2^64)."""
        framework = paper_framework(quantum_queries=2 ** 64)
        total = framework.forking_loss + framework.qrom_loss
        self.assertAlmostEqual(total, 259.0, delta=0.5)

    def test_classical_residual_is_comfortable(self):
        """256 soundness - 64 classical loss = ~190 bits. This is the
        number the placeholder buried under a 512-bit error."""
        framework = paper_framework(quantum_queries=2 ** 64)
        classical_residual = framework.soundness_bits - framework.forking_loss
        self.assertGreater(classical_residual, 185.0)

    def test_conservative_qrom_residual_is_near_zero_at_2_to_64(self):
        """The pessimistic quantum bound is where the margin actually
        vanishes -- and only there. residual_bits_optimistic subtracts the
        FULL conservative QROM loss."""
        framework = paper_framework(quantum_queries=2 ** 64)
        self.assertLess(framework.residual_bits_optimistic, 0.0)
        self.assertGreater(framework.residual_bits_optimistic, -10.0)

    def test_placeholder_error_was_512_bits(self):
        """Pin the size of the correction so the wrong formula can't return."""
        from pqct.forking_bound import forking_report
        report = forking_report(2 ** 64)
        self.assertAlmostEqual(
            report.classical_fs_bits - report.placeholder_residual_bits,
            512.0, delta=1.0,
        )

    def test_loss_scales_once_with_log_q(self):
        """Doubling log2(Q) adds ~log2(Q) to the classical loss, not 5x that."""
        a = paper_framework(quantum_queries=2 ** 32).forking_loss
        b = paper_framework(quantum_queries=2 ** 64).forking_loss
        self.assertAlmostEqual(b - a, 32.0, delta=0.01)


class HonestyTests(unittest.TestCase):
    """A framework that overstates its own status is worse than none."""

    def test_status_is_open_while_obligations_are_undischarged(self):
        framework = paper_framework()
        self.assertTrue(framework.open_obligations)
        self.assertIn("OPEN", framework.overall_status)
        self.assertIn("no Fiat-Shamir security claim", framework.overall_status)

    def test_open_obligations_are_named(self):
        """Three remain open. classical-rewinding-to-3-transcripts moved to
        CODE_EVIDENCED once AFK'22 (the forking lemma) was computed and
        special-soundness machine-checked in pqct/special_soundness."""
        framework = paper_framework()
        open_names = {o.name for o in framework.open_obligations}
        self.assertNotIn("classical-rewinding-to-3-transcripts", open_names)
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
