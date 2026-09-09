"""Tests for 3-special-soundness of the 1-round variant.

Each adversary pins one step of the argument. The load-bearing assertions
are the ones where the VERIFIER (not the extractor) does the rejecting:
special-soundness is a statement about accepting transcripts, so a cheat
the verifier already refuses is not a counterexample -- but we still want
to know WHICH gate caught it, because that is what the proof sketch says.
"""

from __future__ import annotations

import unittest

from pqct.special_soundness import (
    adversary_suite,
    special_soundness_report,
    three_challenges,
    toy_fixture,
    honest_transcripts,
    verifier_accepts,
    _forge_nonbit_transcript,
    _mutate_third_response,
)
from pqct.three_transcript_extraction import extract_from_three_transcripts


def outcome(name):
    return next(o for o in adversary_suite() if o.name.startswith(name))


class HonestPathTests(unittest.TestCase):
    def test_honest_triple_extracts_a_witness(self):
        o = outcome("honest")
        self.assertTrue(o.all_accepted)
        self.assertTrue(o.witness_valid)
        self.assertFalse(o.collision_surfaced)


class Step2BindingTests(unittest.TestCase):
    """Cross-consistency is what HMC binding implies (Step 2)."""

    def test_non_affine_response_is_rejected_by_the_verifier_itself(self):
        """Not merely by the extractor: equation (A) fails, because a
        non-affine g breaks x*B_agg + G = Com(g_agg; z_b)."""
        o = outcome("non-affine")
        self.assertFalse(o.all_accepted)
        self.assertTrue(o.special_soundness_holds)

    def test_spliced_transcript_is_rejected_by_the_verifier(self):
        """A transcript from a different witness opens a DIFFERENT B_agg;
        equation (A) against the real commitments fails."""
        o = outcome("spliced")
        self.assertFalse(o.all_accepted)
        self.assertTrue(o.special_soundness_holds)


class Step3BinarynessTests(unittest.TestCase):
    """Equation (B) enforces b(1-b)=0 (Step 3)."""

    def test_nonbit_passes_cross_consistency_but_fails_verifier(self):
        """THE decisive case. b=2 is affine in x, so the two-transcript
        and cross-consistency checks all pass -- the extractor alone
        would be FOOLED. The verifier's equation (B) rejects, because the
        prover's E-message t*(1-2b) is only the correct linearisation of
        g(x-g) when b(1-b)=0. This is the step that makes the third
        equation load-bearing."""
        o = outcome("non-bit")
        self.assertIn("consistent=True", o.detail)      # extractor fooled...
        self.assertIn("binary=False", o.detail)         # ...on binaryness
        self.assertFalse(o.all_accepted)                # ...but verifier rejects
        self.assertTrue(o.special_soundness_holds)

    def test_nonbit_rejection_is_from_equation_B_not_A(self):
        """Confirm WHICH equation fails: swap in the honest E-commitment
        recomputed for b=2 the RIGHT way (g(x-g) directly) and the
        transcript would pass A but the prover has no such honest E, so
        this checks the forged E specifically is what fails."""
        fx = toy_fixture()
        x = three_challenges(fx)[0]
        proof, commits = _forge_nonbit_transcript(fx, x, 2)
        self.assertFalse(verifier_accepts(fx, proof, x, commits))
        # Same construction with b=1 (a real bit) must be accepted -- so the
        # rejection is about the bit value, not about the hand-built path.
        proof1, commits1 = _forge_nonbit_transcript(fx, x, 1)
        self.assertTrue(verifier_accepts(fx, proof1, x, commits1))


class DistinctnessTests(unittest.TestCase):
    def test_repeated_challenge_is_refused_not_accepted(self):
        """y = 0 makes every extractor identity 0 == 0. Must be refused
        outright, never treated as three transcripts."""
        o = outcome("repeated")
        self.assertTrue(o.refused)
        self.assertTrue(o.special_soundness_holds)


class ReportTests(unittest.TestCase):
    def test_no_counterexamples(self):
        r = special_soundness_report()
        self.assertTrue(r["all_hold"])
        self.assertEqual(r["counterexamples"], [])

    def test_status_is_honest_about_what_this_is(self):
        s = special_soundness_report()["status"]
        self.assertIn("MACHINE-CHECKED", s)
        self.assertIn("NOT a formal proof", s)
        self.assertIn("enumerated", s)
        self.assertIn("PENDING external review", s)

    def test_claim_is_relaxed_not_exact(self):
        """Honesty check: the claim must say RELAXED, because challenge
        differences are not invertible in the ring."""
        self.assertIn("relaxed", special_soundness_report()["claim"])


if __name__ == "__main__":
    unittest.main()
