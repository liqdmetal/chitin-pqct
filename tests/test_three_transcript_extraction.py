"""Tests for three-transcript binary-witness extraction.

Built on REAL Protocol 1 transcripts (same witness, three distinct
challenges), because the whole point is that three genuine transcripts
share one (b, t) while forged ones do not.
"""

import unittest
from types import SimpleNamespace

from pqct.binary_protocol1_ring import (
    RingProtocol1Parameters,
    build_protocol1_ring_transcript,
)
from pqct.hmc import HMCKey, bounded_ring_element, centered_coefficients
from pqct.ring_commitment import RingElement, ToyParameters
from pqct.three_transcript_extraction import (
    ThreeTranscriptError,
    check_cross_consistency,
    check_pairwise_bits_agree,
    check_relaxed_binary,
    extract_all_rows,
    extract_from_three_transcripts,
    extract_relaxed_witness,
)


class ThreeTranscriptTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        one = r((1, 0, 0, 0, 0, 0, 0, 0))
        self.base = HMCKey(
            G_r=((one,),),
            G_m=((one, r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=self.params,
        )
        self.e = HMCKey(
            G_r=((one,),),
            G_m=(tuple(one for _ in range(4)),),
            params=self.params,
        )
        self.f = self.e
        self.g = HMCKey(
            G_r=((one,),),
            G_m=((one, r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=self.params,
        )
        # Two rows of two bits: b = [[0,1],[1,0]].
        self.bits = (
            (r((0,) * 8), r((1, 0, 0, 0, 0, 0, 0, 0))),
            (r((1, 0, 0, 0, 0, 0, 0, 0)), r((0,) * 8)),
        )
        self.openings = (
            (r((2, 0, 0, 0, 0, 0, 0, 0)),),
            (r((3, 0, 0, 0, 0, 0, 0, 0)),),
        )
        self.commitments = tuple(
            self.base.commit(vector, opening)
            for vector, opening in zip(self.bits, self.openings)
        )
        self.masks = (
            (r((1, 1, 0, 0, 0, 0, 0, 0)), r((2, 0, 1, 0, 0, 0, 0, 0))),
            (r((3, 0, 0, 1, 0, 0, 0, 0)), r((4, 1, 0, 0, 0, 0, 0, 0))),
        )
        self.re = (one,)
        self.rf = (r((2, 0, 0, 0, 0, 0, 0, 0)),)
        self.rt = ((one,), (r((2, 0, 0, 0, 0, 0, 0, 0)),))
        self.zeta = one
        self.proof_params = RingProtocol1Parameters(3, 1, 10 ** 6, 10 ** 6, 10 ** 6)
        # Three DISTINCT challenges, one shared witness.
        self.challenges = (
            r((2, 1, 0, 0, 0, 0, 0, 0)),
            r((5, 0, 1, 0, 0, 0, 0, 0)),
            r((7, 2, 0, 0, 0, 0, 0, 0)),
        )
        self.proofs = tuple(
            build_protocol1_ring_transcript(
                b"three", self.base, self.e, self.f, self.g, self.commitments,
                self.bits, self.openings, self.masks, self.re, self.rf, self.rt,
                self.proof_params, zeta=self.zeta, challenge_x=challenge,
            )
            for challenge in self.challenges
        )

    def test_all_positions_extract_and_pass_every_check(self):
        results = extract_all_rows(self.challenges, self.proofs)
        self.assertEqual(len(results), 4)  # 2 rows x 2 columns
        for result in results:
            with self.subTest(row=result.row, column=result.column):
                self.assertTrue(result.cross_consistent)
                self.assertTrue(all(result.binary_ok))
                self.assertTrue(result.pairwise_bits_agree)
                self.assertTrue(result.accepted)

    def test_relaxed_bit_equals_y_times_the_true_bit(self):
        """y*b must match the honest witness times the challenge difference."""
        for row in range(2):
            for column in range(2):
                witness = extract_relaxed_witness(
                    self.challenges, self.proofs, row, column, 0, 1
                )
                expected = witness.relaxation.mul(self.bits[row][column])
                self.assertEqual(witness.relaxed_bit, expected)

    def test_relaxed_mask_equals_minus_y_times_the_true_mask(self):
        """x_b*g_a - x_a*g_b = (x_b - x_a)*t = -y*t, recovering the MASK.

        Two transcripts cannot give this without the cross-multiplication;
        it is the piece a plain divided difference throws away.
        """
        for row in range(2):
            for column in range(2):
                witness = extract_relaxed_witness(
                    self.challenges, self.proofs, row, column, 0, 1
                )
                minus_y = RingElement.zero(self.params).sub(witness.relaxation)
                expected = minus_y.mul(self.masks[row][column])
                self.assertEqual(witness.relaxed_mask, expected)

    def test_relaxed_bit_is_nonzero_for_a_one_bit(self):
        """Sanity: extraction is not trivially returning zero everywhere."""
        witness = extract_relaxed_witness(
            self.challenges, self.proofs, 0, 1, 0, 1
        )  # bits[0][1] == 1
        self.assertNotEqual(witness.relaxed_bit, RingElement.zero(self.params))

    def test_relaxed_bit_is_zero_for_a_zero_bit(self):
        witness = extract_relaxed_witness(
            self.challenges, self.proofs, 0, 0, 0, 1
        )  # bits[0][0] == 0
        self.assertEqual(witness.relaxed_bit, RingElement.zero(self.params))


class ThreeTranscriptAttackTests(ThreeTranscriptTests):
    """Cheating strategies that two transcripts cannot detect."""

    def _stub(self, responses_g):
        return SimpleNamespace(responses_g=responses_g)

    def test_non_affine_responses_fail_cross_consistency(self):
        """THE reason three transcripts matter.

        Two points always fit a line, so a prover whose responses are not
        affine in x is undetectable from a pair. Perturbing only the THIRD
        response leaves both (0,1)-pair checks perfectly happy and is caught
        only by the three-point identity.
        """
        rows = [list(p.responses_g[0]) for p in self.proofs]
        # Perturb transcript 2 only.
        rows[2][0] = rows[2][0].add(self.r((1, 0, 0, 0, 0, 0, 0, 0)))
        stubs = tuple(self._stub((tuple(row),)) for row in rows)

        # The (0,1) pair alone still looks consistent...
        pair_witness = extract_relaxed_witness(
            self.challenges, stubs, 0, 0, 0, 1
        )
        self.assertEqual(
            pair_witness.relaxed_bit,
            extract_relaxed_witness(self.challenges, self.proofs, 0, 0, 0, 1
                                    ).relaxed_bit,
        )
        # ...but the three-point test catches it.
        self.assertFalse(check_cross_consistency(self.challenges, stubs, 0, 0))
        result = extract_from_three_transcripts(self.challenges, stubs, 0, 0)
        self.assertFalse(result.accepted)

    def test_non_bit_witness_fails_the_binary_check(self):
        """A relaxed opening of 2 (not a bit) must fail B*(y-B) == 0."""
        two = self.r((2, 0, 0, 0, 0, 0, 0, 0))
        rows = []
        for challenge in self.challenges:
            # g = x*2 + t with t = 0, a perfectly affine but NON-BIT witness.
            rows.append((challenge.mul(two),))
        stubs = tuple(self._stub((row,)) for row in rows)
        # Affine, so cross-consistency PASSES...
        self.assertTrue(check_cross_consistency(self.challenges, stubs, 0, 0))
        # ...but it is not a bit.
        result = extract_from_three_transcripts(self.challenges, stubs, 0, 0)
        self.assertFalse(all(result.binary_ok))
        self.assertFalse(result.accepted)

    def test_inconsistent_slopes_fail_pairwise_agreement(self):
        """Responses affine per-pair but with different b per pair."""
        one = self.r((1, 0, 0, 0, 0, 0, 0, 0))
        three = self.r((3, 0, 0, 0, 0, 0, 0, 0))
        rows = (
            (self.challenges[0].mul(one),),
            (self.challenges[1].mul(one),),
            (self.challenges[2].mul(three),),  # different slope
        )
        stubs = tuple(self._stub((row,)) for row in rows)
        result = extract_from_three_transcripts(self.challenges, stubs, 0, 0)
        self.assertFalse(result.accepted)

    def test_repeated_challenge_is_refused(self):
        """A duplicate challenge zeroes the relaxation and makes every check
        vacuously true -- it must be refused, not accepted."""
        duplicated = (self.challenges[0], self.challenges[0], self.challenges[1])
        with self.assertRaises(ThreeTranscriptError) as context:
            extract_from_three_transcripts(duplicated, self.proofs, 0, 0)
        self.assertIn("distinct", str(context.exception))

    def test_wrong_transcript_count_is_refused(self):
        with self.assertRaises(ThreeTranscriptError):
            extract_from_three_transcripts(
                self.challenges[:2], self.proofs[:2], 0, 0
            )

    def test_out_of_range_position_is_refused(self):
        with self.assertRaises(ThreeTranscriptError):
            extract_from_three_transcripts(self.challenges, self.proofs, 9, 0)

    def test_zero_relaxation_would_make_checks_vacuous(self):
        """Documents WHY distinctness is enforced: with y = 0 the binary
        check passes for absolutely anything."""
        zero = RingElement.zero(self.params)
        fake = SimpleNamespace(
            row=0, column=0, pair=(0, 1),
            relaxation=zero, relaxed_bit=zero, relaxed_mask=zero,
        )
        self.assertTrue(check_relaxed_binary(fake))


if __name__ == "__main__":
    unittest.main()
