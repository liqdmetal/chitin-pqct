import unittest

from pqct.balance_composition import BalanceCompositionError
from pqct.balance_composition import SignedAmount
from pqct.balance_composition import build_balance_columns
from pqct.balance_composition import build_masked_balance_response


class BalanceCompositionTests(unittest.TestCase):
    def test_conserved_three_amounts(self):
        amounts = (SignedAmount(100, 1), SignedAmount(50, 1), SignedAmount(150, -1))
        cols = build_balance_columns(amounts, 8)
        self.assertTrue(cols.conserved)
        self.assertEqual(cols.weighted_sum, 0)
        self.assertEqual(len(cols.columns), 8)

    def test_single_debit_and_credit(self):
        amounts = (SignedAmount(10, 1), SignedAmount(10, -1))
        cols = build_balance_columns(amounts, 8)
        self.assertTrue(cols.conserved)

    def test_non_conserved_detected(self):
        amounts = (SignedAmount(100, 1), SignedAmount(30, -1))
        cols = build_balance_columns(amounts, 8)
        self.assertFalse(cols.conserved)
        self.assertNotEqual(cols.weighted_sum, 0)

    def test_overflow_carries_but_mod_2k_conserved(self):
        # 200 + 200 = 400 = 144 mod 256, but as 8-bit unsigned both fit.
        # A transfer conserving mod 2^k (with 256 wrap) is the paper's
        # corrector-free case (eq. 10-11 discussion): c_j captures the
        # carry structure and sum 2^j c_j == 0 in 2^k arithmetic.
        amounts = (SignedAmount(200, 1), SignedAmount(200, 1), SignedAmount(400, -1))
        # 400 does not fit in 8 bits, so this must reject at range check.
        with self.assertRaises(BalanceCompositionError):
            build_balance_columns(amounts, 8)

    def test_wide_bit_width_handles_large_amounts(self):
        amounts = (SignedAmount(300, 1), SignedAmount(300, -1))
        cols = build_balance_columns(amounts, 16)
        self.assertTrue(cols.conserved)

    def test_invalid_sign_rejected(self):
        amounts = (SignedAmount(5, 2),)
        with self.assertRaises(BalanceCompositionError):
            build_balance_columns(amounts, 8)

    def test_empty_amounts_rejected(self):
        with self.assertRaises(BalanceCompositionError):
            build_balance_columns((), 8)

    def test_zero_bit_width_rejected(self):
        with self.assertRaises(BalanceCompositionError):
            build_balance_columns((SignedAmount(5, 1),), 0)


class MaskedBalanceResponseTests(unittest.TestCase):
    def test_masked_response_conserved_is_exact_zero(self):
        amounts = (SignedAmount(100, 1), SignedAmount(50, 1), SignedAmount(150, -1))
        cols = build_balance_columns(amounts, 8)
        # cycle mask sampled vector length must be cols+1 = 9 with zero ends
        resp = build_masked_balance_response(cols.columns, 3, (0, 1, 0, -1, 1, 0, -1, 1, 0))
        self.assertTrue(resp.response_relation_exact)
        self.assertEqual(resp.weighted_response, 0)

    def test_mask_dimension_mismatch_rejected(self):
        with self.assertRaises(BalanceCompositionError):
            build_masked_balance_response((0, 1, 0), 3, (0, 1, 0))

    def test_zero_challenge_rejected(self):
        with self.assertRaises(BalanceCompositionError):
            build_masked_balance_response((0, 1, 0), 0, (0, 1, 0, 0))


if __name__ == "__main__":
    unittest.main()
