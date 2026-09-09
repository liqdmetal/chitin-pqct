"""Tests for two-transcript extraction and its limits.

The decisive test is test_non_affine_prover_passes_at_t2_but_fails_at_t3:
it demonstrates that the 64-bit forking saving is NOT free, because the
cheating prover two transcripts cannot see is caught by three.
"""

import unittest
from types import SimpleNamespace

from pqct.binary_protocol1_ring import (
    RingProtocol1Parameters,
    build_protocol1_ring_transcript,
)
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.ring_commitment import RingElement, ToyParameters
from pqct.three_transcript_extraction import (
    ThreeTranscriptError,
    check_cross_consistency,
    extract_from_three_transcripts,
)
from pqct.two_transcript_extraction import (
    binary_relation_source,
    extract_from_two_transcripts,
    verify_two_transcript_consistency,
)


class TwoTranscriptTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda v: bounded_ring_element(v, self.params)
        self.r = r
        one = r((1, 0, 0, 0, 0, 0, 0, 0))
        self.base = HMCKey(
            G_r=((one,),), G_m=((one, r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=self.params,
        )
        self.e = HMCKey(
            G_r=((one,),), G_m=(tuple(one for _ in range(4)),),
            params=self.params,
        )
        self.f = self.e
        self.g = HMCKey(
            G_r=((one,),), G_m=((one, r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=self.params,
        )
        self.bits = (
            (r((0,) * 8), r((1, 0, 0, 0, 0, 0, 0, 0))),
            (r((1, 0, 0, 0, 0, 0, 0, 0)), r((0,) * 8)),
        )
        self.openings = (
            (r((2, 0, 0, 0, 0, 0, 0, 0)),), (r((3, 0, 0, 0, 0, 0, 0, 0)),),
        )
        self.commitments = tuple(
            self.base.commit(v, o) for v, o in zip(self.bits, self.openings)
        )
        self.masks = (
            (r((1, 1, 0, 0, 0, 0, 0, 0)), r((2, 0, 1, 0, 0, 0, 0, 0))),
            (r((3, 0, 0, 1, 0, 0, 0, 0)), r((4, 1, 0, 0, 0, 0, 0, 0))),
        )
        self.re = (one,)
        self.rf = (r((2, 0, 0, 0, 0, 0, 0, 0)),)
        self.rt = ((one,), (r((2, 0, 0, 0, 0, 0, 0, 0)),))
        self.proof_params = RingProtocol1Parameters(3, 1, 10 ** 6, 10 ** 6, 10 ** 6)
        self.challenges = (
            r((2, 1, 0, 0, 0, 0, 0, 0)),
            r((5, 0, 1, 0, 0, 0, 0, 0)),
            r((7, 2, 0, 0, 0, 0, 0, 0)),
        )
        self.proofs = tuple(
            build_protocol1_ring_transcript(
                b"two", self.base, self.e, self.f, self.g, self.commitments,
                self.bits, self.openings, self.masks, self.re, self.rf,
                self.rt, self.proof_params, zeta=r((1, 0, 0, 0, 0, 0, 0, 0)),
                challenge_x=challenge,
            )
            for challenge in self.challenges
        )

    def test_recovers_both_relaxed_values(self):
        for row in range(2):
            for column in range(2):
                extraction = extract_from_two_transcripts(
                    self.challenges[:2], self.proofs[:2], row, column
                )
                expected_bit = extraction.relaxation.mul(self.bits[row][column])
                self.assertEqual(extraction.relaxed_bit, expected_bit)
                minus_y = RingElement.zero(self.params).sub(extraction.relaxation)
                self.assertEqual(
                    extraction.relaxed_mask,
                    minus_y.mul(self.masks[row][column]),
                )

    def test_binary_check_holds_for_honest_bits(self):
        for row in range(2):
            for column in range(2):
                extraction = extract_from_two_transcripts(
                    self.challenges[:2], self.proofs[:2], row, column
                )
                self.assertTrue(extraction.binary_ok)

    def test_affine_check_is_reported_unavailable(self):
        extraction = extract_from_two_transcripts(
            self.challenges[:2], self.proofs[:2], 0, 0
        )
        self.assertFalse(extraction.affine_check_available)
        self.assertIn("undetectable", extraction.summary()["limitation"])

    def test_repeated_challenge_refused(self):
        with self.assertRaises(ThreeTranscriptError):
            extract_from_two_transcripts(
                (self.challenges[0], self.challenges[0]), self.proofs[:2], 0, 0
            )

    def test_wrong_count_refused(self):
        with self.assertRaises(ThreeTranscriptError):
            extract_from_two_transcripts(
                self.challenges, self.proofs, 0, 0
            )


class TautologyTests(TwoTranscriptTests):
    """The t=2 'consistency check' must be shown to be empty."""

    def _stub(self, rows):
        return SimpleNamespace(responses_g=rows)

    def test_consistency_holds_for_honest_transcripts(self):
        self.assertTrue(
            verify_two_transcript_consistency(
                self.challenges[:2], self.proofs[:2], 0, 0
            )
        )

    def test_consistency_also_holds_for_ARBITRARY_responses(self):
        """The point: it is a tautology. Random g values still 'pass',
        because (b,t) was solved from them."""
        for values in ((3, 5), (11, 2), (0, 7), (100, 250)):
            rows = tuple(
                self._stub(((self.r((v,) + (0,) * 7),),)) for v in values
            )
            with self.subTest(values=values):
                self.assertTrue(
                    verify_two_transcript_consistency(
                        self.challenges[:2], rows, 0, 0
                    ),
                    "a tautology must never fail -- if it can, it is not one",
                )

    def test_non_affine_prover_passes_at_t2_but_fails_at_t3(self):
        """THE decisive result for the 64-bit question.

        A prover whose third response breaks affineness is invisible to any
        pair of transcripts and caught only by the three-point identity. So
        dropping to t=2 does not merely cost redundancy -- it removes the
        only transcript-level test of the binary relation.
        """
        rows = [list(p.responses_g[0]) for p in self.proofs]
        rows[2][0] = rows[2][0].add(self.r((1,) + (0,) * 7))
        stubs = tuple(self._stub((tuple(row),)) for row in rows)

        # Every PAIR still looks fine.
        for pair in ((0, 1), (0, 2), (1, 2)):
            challenges = (self.challenges[pair[0]], self.challenges[pair[1]])
            proofs = (stubs[pair[0]], stubs[pair[1]])
            with self.subTest(pair=pair):
                self.assertTrue(
                    verify_two_transcript_consistency(challenges, proofs, 0, 0)
                )

        # The triple does not.
        self.assertFalse(check_cross_consistency(self.challenges, stubs, 0, 0))
        self.assertFalse(
            extract_from_three_transcripts(self.challenges, stubs, 0, 0).accepted
        )


class ForkingSavingTests(unittest.TestCase):
    def test_the_saving_is_documented_as_unresolved(self):
        """No claiming 64 bits back on an unresolved question."""
        source = binary_relation_source()
        self.assertIn("UNRESOLVED", source["status"])
        self.assertEqual(source["forking_loss_bits_at_2_64"]["t=2"], 64.0)
        self.assertEqual(source["forking_loss_bits_at_2_64"]["t=3"], 128.0)

    def test_both_branches_of_the_question_are_stated(self):
        source = binary_relation_source()
        self.assertIn("t=2 suffices", source["if_per_transcript"])
        self.assertIn("cannot be recovered", source["if_cross_transcript"])

    def test_forking_framework_agrees_with_the_quoted_numbers(self):
        from pqct.fiat_shamir_framework import forking_loss_bits

        self.assertAlmostEqual(forking_loss_bits(2 ** 64, 2), 64.0, places=6)
        self.assertAlmostEqual(forking_loss_bits(2 ** 64, 3), 128.0, places=6)


if __name__ == "__main__":
    unittest.main()
