"""Tests for the Protocol 5 unreduced integer trace.

The load-bearing test is test_modular_cheat_shows_as_agrees_but_overflowed:
a prover whose weighted sum is a nonzero MULTIPLE of q satisfies every R_q
equation while the integer statement is false. That is the exact cheat
Protocol 5 exists to prevent, and the trace must expose it as
"agrees mod q" AND "overflowed" rather than reporting everything fine.
"""

import unittest
from decimal import Decimal

from pqct.balance_composition import SignedAmount, build_balance_columns
from pqct.hmc import bounded_ring_element
from pqct.matrix_generation import generate_hmc_key
from pqct.protocol5 import (
    derive_ring_cycle_mask,
    protocol5_params_for_lambdas,
    prove_linear_equation,
)
from pqct.protocol5_integer_trace import (
    Observation,
    Protocol5TraceError,
    Protocol5TraceReport,
    trace_cycle_mask,
    trace_protocol5,
)
from pqct.ring_commitment import ToyParameters


class ObservationTests(unittest.TestCase):
    def test_in_window_and_overflow_are_complementary(self):
        q = 17
        inside = Observation("a", (8, -8), (8, -8), q)
        self.assertTrue(inside.in_window)
        self.assertFalse(inside.overflowed)
        outside = Observation("b", (9, 0), (9, 0), q)
        self.assertFalse(outside.in_window)
        self.assertTrue(outside.overflowed)

    def test_agreement_is_modular(self):
        q = 17
        # 18 == 1 mod 17, so these agree mod q but the integer differs.
        observation = Observation("c", (18,), (1,), q)
        self.assertTrue(observation.agrees_mod_q)
        self.assertTrue(observation.overflowed)

    def test_max_abs_reported(self):
        self.assertEqual(Observation("d", (3, -9, 4), (0, 0, 0), 17).max_abs, 9)


class CycleMaskTraceTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.r = lambda v: bounded_ring_element(v, self.params)

    def test_honest_mask_telescopes_to_exactly_zero_over_Z(self):
        tail = (
            self.r((3, 1, -2, 0, 0, 0, 0, 0)),
            self.r((-1, 2, 0, 0, 0, 0, 0, 0)),
        )
        mask = derive_ring_cycle_mask(tail, self.params)
        observation = trace_cycle_mask(mask, self.params.q)
        self.assertTrue(observation.agrees_mod_q)
        self.assertTrue(observation.in_window)
        self.assertEqual(observation.max_abs, 0, "must be EXACTLY zero over Z")

    def test_tampered_mask_breaks_the_identity(self):
        tail = (self.r((3, 0, 0, 0, 0, 0, 0, 0)), self.r((1, 0, 0, 0, 0, 0, 0, 0)))
        mask = list(derive_ring_cycle_mask(tail, self.params))
        mask[0] = mask[0].add(self.r((1, 0, 0, 0, 0, 0, 0, 0)))
        observation = trace_cycle_mask(tuple(mask), self.params.q)
        self.assertNotEqual(observation.max_abs, 0)

    def test_empty_mask_refused(self):
        with self.assertRaises(Protocol5TraceError):
            trace_cycle_mask((), self.params.q)


class HonestTranscriptTraceTests(unittest.TestCase):
    """Trace a REAL Protocol 5 transcript end to end."""

    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=5)
        self.m, self.k = 2, 5
        self.key = generate_hmc_key(b"p5trace|key", self.params, self.m, self.k)
        self.amounts = (SignedAmount(10, 1), SignedAmount(6, 1), SignedAmount(16, -1))
        self.signs = tuple(a.sign for a in self.amounts)
        self.p5 = protocol5_params_for_lambdas(
            self.signs, p=2, w=4, k=self.k, B=1, m=self.m, d=8,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )
        self.result = prove_linear_equation(
            seed=b"p5trace", statement=b"p5trace-statement", key=self.key,
            amounts=self.amounts, bit_width=self.k, p5=self.p5,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )

    def test_honest_columns_sum_to_zero_over_the_integers(self):
        columns = build_balance_columns(self.amounts, self.k)
        self.assertTrue(columns.conserved)
        self.assertEqual(columns.weighted_sum, 0)

    def test_reconstruction_and_columns_are_traced(self):
        columns = build_balance_columns(self.amounts, self.k)
        report = trace_protocol5(
            q=self.params.q,
            challenge=self.result.challenge_x,
            columns=columns.columns,
            mask=self.result.proof.commitment_d,  # shape stand-in
            response_tail=self.result.proof.response_tail,
            openings=(),
            lambdas=self.signs,
            mask_randomness=(),
            response_z=self.result.proof.response_z,
        )
        names = [o.name for o in report.observations]
        self.assertIn("cycle_mask_weighted_sum", names)
        self.assertIn("column_weighted_sum", names)
        self.assertIn("f0_reconstruction", names)
        # The honest column sum is exactly zero over Z.
        column_obs = next(
            o for o in report.observations if o.name == "column_weighted_sum"
        )
        self.assertEqual(column_obs.max_abs, 0)
        self.assertTrue(column_obs.in_window)


class ModularCheatTests(unittest.TestCase):
    """The cheat Protocol 5 exists to stop, and how the trace exposes it."""

    def test_modular_cheat_shows_as_agrees_but_overflowed(self):
        """weighted_sum == q: zero mod q, NOT zero over the integers.

        Every R_q check passes. Only the integer view reveals the fraud, and
        the trace must label it precisely: agrees_mod_q True, overflowed True.
        """
        q = 17
        report = Protocol5TraceReport(q=q)
        # An integer value of exactly q: reduces to 0, but is not 0.
        observation = report.record("column_weighted_sum", (q,), (0,))
        self.assertTrue(observation.agrees_mod_q, "R_q check passes")
        self.assertTrue(observation.overflowed, "integer statement is FALSE")
        self.assertFalse(report.safe, "safe must require in-range, not just agreement")
        self.assertIn("column_weighted_sum", report.overflowed_names)

    def test_multiple_of_q_is_also_caught(self):
        q = 17
        report = Protocol5TraceReport(q=q)
        report.record("column_weighted_sum", (3 * q,), (0,))
        self.assertFalse(report.safe)

    def test_honest_in_range_value_is_safe(self):
        q = 12289
        report = Protocol5TraceReport(q=q)
        report.record("a", (5, -3), (5, -3))
        report.record("b", (0, 0), (0, 0))
        self.assertTrue(report.safe)
        self.assertEqual(report.overflowed_names, ())
        self.assertEqual(report.disagreeing_names, ())

    def test_disagreement_is_reported_separately_from_overflow(self):
        """A wrong value that stays in range is a different failure mode."""
        q = 12289
        report = Protocol5TraceReport(q=q)
        report.record("a", (5,), (6,))
        self.assertFalse(report.all_agree)
        self.assertFalse(report.any_overflow)
        self.assertFalse(report.safe)
        self.assertIn("a", report.disagreeing_names)

    def test_empty_report_is_not_safe(self):
        """No observations must not read as 'safe' -- vacuous truth is a lie."""
        self.assertFalse(Protocol5TraceReport(q=17).safe)

    def test_summary_exposes_the_verdict(self):
        report = Protocol5TraceReport(q=17)
        report.record("x", (17,), (0,))
        summary = report.summary()
        self.assertFalse(summary["safe"])
        self.assertTrue(summary["any_overflow"])
        self.assertEqual(summary["recorded"], 1)


if __name__ == "__main__":
    unittest.main()
