"""Tests for the QROM bound, settled by Don-Fehr-Majenz CRYPTO'20.

The substantive things to pin: (1) the loss is the ACTUAL theorem, not a
placeholder, and it is tight, so nobody goes looking for a better
citation; (2) the 1-round alternative is worth ~130 bits and is the only
structural route to a positive QROM residual, so the zeta work's stakes
are recorded in code.
"""

from __future__ import annotations

import math
import unittest

from pqct.qrom_bound import (
    QROMError,
    dfm20_additive_error_bits,
    dfm20_multiround_loss_bits,
    one_round_alternative,
    placeholder_loss_bits,
    qrom_report,
)


class TheoremArithmeticTests(unittest.TestCase):
    def test_two_round_loss_at_2_to_64(self):
        """n!/(2q+n+1)^(2n), n=2: 4*log2(2^65+3) - 1 ~ 259.0 bits."""
        self.assertAlmostEqual(dfm20_multiround_loss_bits(2 ** 64, 2), 259.0, delta=0.01)

    def test_one_round_loss_at_2_to_64(self):
        """n=1: 2*log2(2^65+2) - 0 ~ 130.0 bits."""
        self.assertAlmostEqual(dfm20_multiround_loss_bits(2 ** 64, 1), 130.0, delta=0.01)

    def test_n_factorial_credit_is_the_only_improvement(self):
        """The real theorem beats the placeholder by exactly log2(n!) plus
        the negligible (n+1 vs 1) inside the log -- ~1 bit at n=2. That is
        the whole improvement, and it should be recorded as such."""
        real = dfm20_multiround_loss_bits(2 ** 64, 2)
        placeholder = placeholder_loss_bits(2 ** 64, 2)
        self.assertAlmostEqual(placeholder - real, 1.0, delta=0.01)

    def test_loss_grows_with_2n_log_q(self):
        a = dfm20_multiround_loss_bits(2 ** 32, 2)
        b = dfm20_multiround_loss_bits(2 ** 64, 2)
        self.assertAlmostEqual(b - a, 4 * 32.0, delta=0.01)

    def test_additive_error_is_negligible(self):
        """n!/|C| with |C| ~ 2^256: about -255 bits."""
        bits = dfm20_additive_error_bits(2 ** 256, 2)
        self.assertLess(bits, -250.0)

    def test_rejects_bad_input(self):
        with self.assertRaises(QROMError):
            dfm20_multiround_loss_bits(0, 2)
        with self.assertRaises(QROMError):
            dfm20_multiround_loss_bits(2 ** 64, 0)


class ReportTests(unittest.TestCase):
    def test_residual_is_slightly_negative_and_that_is_the_truth(self):
        """254.5 - 259.0 = -4.5. Under the TIGHT QROM bound a 2-round
        protocol at Q=2^64 has no margin. Not a bookkeeping artifact."""
        r = qrom_report(2 ** 64)
        self.assertAlmostEqual(r.residual_bits, -4.5, delta=0.1)

    def test_report_is_marked_established_and_tight(self):
        s = qrom_report(2 ** 64).summary()
        self.assertTrue(s["established"])
        self.assertTrue(s["tight"])
        self.assertIn("Don-Fehr-Majenz", s["theorem"])
        self.assertIn("TIGHT", s["theorem"])

    def test_improvement_over_placeholder_is_recorded_honestly(self):
        s = qrom_report(2 ** 64).summary()
        self.assertAlmostEqual(s["improvement_over_placeholder_bits"], 1.0, delta=0.01)


class OneRoundAlternativeTests(unittest.TestCase):
    """The stakes of the zeta work, in code."""

    def test_one_round_residual_is_comfortably_positive(self):
        alt = one_round_alternative(2 ** 64)
        self.assertGreater(alt["one_round_residual_bits"], 120.0)

    def test_gain_is_about_130_bits(self):
        alt = one_round_alternative(2 ** 64)
        self.assertAlmostEqual(alt["gain_bits"], 129.6, delta=0.5)

    def test_dependency_names_the_open_obligation(self):
        dep = one_round_alternative(2 ** 64)["dependency"]
        self.assertIn("non-adaptive zeta", dep)
        self.assertIn("cancellation", dep)
        self.assertIn("grinding", dep)
        self.assertIn("special-soundness", dep)
        self.assertIn("remaining obligation", dep)


if __name__ == "__main__":
    unittest.main()
