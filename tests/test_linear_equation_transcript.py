import unittest

from pqct.hmc import HMCKey, bounded_ring_element
from pqct.linear_equation_transcript import LinearEquationError
from pqct.linear_equation_transcript import build_cycle_mask_commitment
from pqct.linear_equation_transcript import check_commitment_equation
from pqct.linear_equation_transcript import compute_response_tail
from pqct.linear_equation_transcript import f0_in_canonical_range
from pqct.linear_equation_transcript import reconstruct_f0_over_integers
from pqct.ring_commitment import RingElement, ToyParameters


class LinearEquationTranscriptTests(unittest.TestCase):
    def setUp(self):
        # Small modulus q=17 so the overflow gate is actually reachable:
        # with q=12289 and k=8 the weighted column sum can never approach
        # q, making the f0-in-range check vacuous. q=17 exercises it.
        self.params = ToyParameters(n=8, q=17, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        self.unit = r((1, 0, 0, 0, 0, 0, 0, 0))
        self.key = HMCKey(((self.unit,),), ((self.unit,) * 8,), self.params)
        self.zero_mask = build_cycle_mask_commitment(
            self.key, (0,) * 9, (self.unit,)
        )

    def test_cycle_mask_weighted_sum_is_zero(self):
        commit = build_cycle_mask_commitment(
            self.key, (0, 3, -2, 1, 4, -1, 2, 0, 0), (self.unit,)
        )
        self.assertEqual(commit.mask.weighted_sum(), 0)

    def test_honest_columns_reconstruct_f0_in_range(self):
        cols = (2, -1, 0, 0, 0, 0, 0, 0)  # weighted = 2 - 2 = 0 over Z
        tail = compute_response_tail(self.unit, cols, self.zero_mask.mask)
        f0 = reconstruct_f0_over_integers(tail)
        self.assertTrue(f0_in_canonical_range(f0, self.params.q))

    def test_overflow_cheat_is_caught_by_f0_range_gate(self):
        """c with sum 2^j c_j == q (0 mod q, nonzero over Z) must fail.

        This is the exact attack Gao's "compute f0 over R, reject unless
        f0 in R_q" step defeats: the mod-q commitment equation alone
        would pass, but integer reconstruction exposes the wraparound.
        """
        cheat_cols = (1, 0, 0, 0, 1, 0, 0, 0)  # weighted = 1 + 16 = 17 = q
        tail = compute_response_tail(self.unit, cheat_cols, self.zero_mask.mask)
        f0 = reconstruct_f0_over_integers(tail)
        self.assertFalse(f0_in_canonical_range(f0, self.params.q))

    def test_commitment_equation_holds_for_honest_transcript(self):
        cols = (2, -1, 0, 0, 0, 0, 0, 0)
        r_c = (self.r((2, 0, 0, 0, 0, 0, 0, 0)),)
        r_d = (self.r((1, 0, 0, 0, 0, 0, 0, 0)),)
        c_elements = tuple(
            self.r((value,) + (0,) * 7) for value in cols
        )
        c_commit = self.key.commit(c_elements, r_c)
        mask_commit = build_cycle_mask_commitment(self.key, (0,) * 9, r_d)
        x = self.r((5, 1, 0, 0, 0, 0, 0, 0))
        tail = compute_response_tail(x, cols, mask_commit.mask)
        f0_int = reconstruct_f0_over_integers(tail)
        f0_element = RingElement.from_coeffs(
            tuple(value % self.params.q for value in f0_int), self.params
        )
        z = tuple(
            x.mul(rc).add(rd) for rc, rd in zip(r_c, r_d)
        )
        self.assertTrue(check_commitment_equation(
            self.key, x, c_commit, mask_commit.commitment,
            f0_element, tail, z,
        ))

    def test_commitment_equation_fails_for_wrong_randomness(self):
        cols = (2, -1, 0, 0, 0, 0, 0, 0)
        r_c = (self.r((2, 0, 0, 0, 0, 0, 0, 0)),)
        r_d = (self.r((1, 0, 0, 0, 0, 0, 0, 0)),)
        c_elements = tuple(self.r((value,) + (0,) * 7) for value in cols)
        c_commit = self.key.commit(c_elements, r_c)
        mask_commit = build_cycle_mask_commitment(self.key, (0,) * 9, r_d)
        x = self.r((5, 1, 0, 0, 0, 0, 0, 0))
        tail = compute_response_tail(x, cols, mask_commit.mask)
        f0_int = reconstruct_f0_over_integers(tail)
        f0_element = RingElement.from_coeffs(
            tuple(value % self.params.q for value in f0_int), self.params
        )
        wrong_z = (self.r((9, 9, 0, 0, 0, 0, 0, 0)),)
        self.assertFalse(check_commitment_equation(
            self.key, x, c_commit, mask_commit.commitment,
            f0_element, tail, wrong_z,
        ))

    def test_mask_length_must_match_key_message_width(self):
        with self.assertRaises(LinearEquationError):
            build_cycle_mask_commitment(self.key, (0, 1, 0), (self.unit,))

    def test_bad_cycle_mask_endpoints_rejected(self):
        with self.assertRaises(LinearEquationError):
            build_cycle_mask_commitment(
                self.key, (1, 0, 0, 0, 0, 0, 0, 0, 0), (self.unit,)
            )

    def test_response_tail_length(self):
        cols = (2, -1, 0, 0, 0, 0, 0, 0)
        tail = compute_response_tail(self.unit, cols, self.zero_mask.mask)
        self.assertEqual(len(tail), len(cols) - 1)


if __name__ == "__main__":
    unittest.main()
