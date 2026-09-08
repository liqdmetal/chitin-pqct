"""Tests for the equations (38)-(45) bounded oracle.

See pqct/protocol1_binary_relation.py module docstring for exactly what
this oracle checks and does not check (it verifies a caller-supplied true
witness against the paper's downstream algebra; it does not extract the
witness from commitments).
"""

import unittest

from pqct.hmc import bounded_ring_element, centered_coefficients
from pqct.protocol1_binary_relation import (
    BinaryEquationError,
    verify_binary_relation_equations_38_45,
)
from pqct.ring_commitment import ToyParameters


class Equations38To45Tests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.r = lambda values: bounded_ring_element(values, self.params)

    def _build_consistent_case(self, bit_value):
        """Construct x0,x1,x2,g_k,y,y_zeta,e_hat,s_hat honestly.

        b_ij is taken as a constant-poly 0 or 1 witness; t_ij is a small
        mask. e_hat/s_hat are derived directly from the paper's h_{i,j} =
        g_{i,j}*(x - g_{i,j}) construction restricted to a single (x,x')
        pair, matching eq. (39): y*h = x*e_hat + s_hat with y = x - x'
        computed over the SAME unreduced integers used by the oracle, so
        the fixture is self-consistent by construction rather than a
        pre-existing accepted-transcript extraction.
        """
        r = self.r
        b_ij = r((bit_value,) + (0,) * (self.params.n - 1))
        t_ij = r((3,) + (0,) * (self.params.n - 1))
        x0 = r((5, 1, 0, 0, 0, 0, 0, 0))
        x1 = r((2, 1, 0, 0, 0, 0, 0, 0))
        x2 = r((7, 0, 1, 0, 0, 0, 0, 0))
        y_zeta = r((4, 0, 0, 1, 0, 0, 0, 0))

        def g_of(x):
            return x.mul(b_ij).add(t_ij)

        gs = (g_of(x0), g_of(x1), g_of(x2))
        y = x0.sub(x1)

        # h_k = g_k * (x_k - g_k); derive e_hat, s_hat from the (0,1) pair
        # via y*h0 - y*h1... but the paper's relation is per-transcript
        # y*h_k = x_k*e_hat + s_hat with a SHARED (e_hat, s_hat). Solve
        # directly from the two linear equations at k=0,1.
        def h_of(x, g):
            return g.mul(x.sub(g))

        h0 = h_of(x0, gs[0])
        h1 = h_of(x1, gs[1])
        # y*h0 = x0*e + s ; y*h1 = x1*e + s  =>  y*(h0-h1) = (x0-x1)*e = y*e
        # => e = h0 - h1 ; s = y*h0 - x0*e
        e_hat = h0.sub(h1)
        s_hat = y.mul(h0).sub(x0.mul(e_hat))
        return x0, x1, x2, gs, y, y_zeta, b_ij, t_ij, e_hat, s_hat

    def test_binary_witness_zero_is_fully_consistent(self):
        x0, x1, x2, gs, y, y_zeta, b_ij, t_ij, e_hat, s_hat = self._build_consistent_case(0)
        check = verify_binary_relation_equations_38_45(
            (x0, x1, x2), gs, y, y_zeta, b_ij, t_ij, e_hat, s_hat, row=0, column=0,
        )
        self.assertTrue(all(check.equation_41_mod_q_ok))
        self.assertTrue(all(check.equation_44_rows_ok))
        self.assertTrue(check.equation_45_holds)
        self.assertTrue(check.quadratic_unknown_is_zero)
        self.assertTrue(check.witness_matches_zero)
        self.assertFalse(check.witness_matches_yy)
        self.assertTrue(check.fully_consistent)

    def test_binary_witness_one_is_fully_consistent(self):
        # b_ij is the TRUE bit (1 here); the module internally scales it
        # to b_hat = y*y_zeta*b for the eq.(44)/(45) closing comparison,
        # so witness_matches_yy compares b_hat (not the raw bit) to Y.
        x0, x1, x2, gs, y, y_zeta, b_ij, t_ij, e_hat, s_hat = self._build_consistent_case(1)
        check = verify_binary_relation_equations_38_45(
            (x0, x1, x2), gs, y, y_zeta, b_ij, t_ij, e_hat, s_hat, row=1, column=2,
        )
        self.assertTrue(check.fully_consistent)
        self.assertTrue(check.witness_matches_yy)
        self.assertFalse(check.witness_matches_zero)

    def test_non_binary_witness_breaks_equation_45(self):
        r = self.r
        x0 = r((5, 1, 0, 0, 0, 0, 0, 0))
        x1 = r((2, 1, 0, 0, 0, 0, 0, 0))
        x2 = r((7, 0, 1, 0, 0, 0, 0, 0))
        y_zeta = r((4, 0, 0, 1, 0, 0, 0, 0))
        y = x0.sub(x1)
        # b_ij deliberately not in {0, y*y_zeta}: pick a value with no
        # special relation to y*y_zeta.
        b_ij = r((2,) + (0,) * (self.params.n - 1))
        t_ij = r((3,) + (0,) * (self.params.n - 1))

        def g_of(x):
            return x.mul(b_ij).add(t_ij)

        gs = (g_of(x0), g_of(x1), g_of(x2))

        def h_of(x, g):
            return g.mul(x.sub(g))

        h0 = h_of(x0, gs[0])
        h1 = h_of(x1, gs[1])
        e_hat = h0.sub(h1)
        s_hat = y.mul(h0).sub(x0.mul(e_hat))

        check = verify_binary_relation_equations_38_45(
            (x0, x1, x2), gs, y, y_zeta, b_ij, t_ij, e_hat, s_hat, row=0, column=0,
        )
        # e_hat/s_hat were solved to make eq.(41) hold exactly at x0 and x1
        # only; eq.(41) at x2 (and hence eq.(44)'s rows, and eq.(45))
        # additionally require b_ij*(1-b_ij) = 0, i.e. a binary bit. With
        # a non-binary b_ij, eq.(41) at x2 -- and everything downstream --
        # fails, which is exactly the paper's soundness argument for why
        # a cheating prover cannot pass all three transcripts unless the
        # witness is binary.
        self.assertFalse(check.equation_41_mod_q_ok[2])
        self.assertFalse(check.quadratic_unknown_is_zero)
        self.assertFalse(check.equation_45_holds)
        self.assertFalse(check.witness_matches_zero)
        self.assertFalse(check.witness_matches_yy)
        self.assertFalse(check.fully_consistent)

    def test_rejects_non_distinct_challenges(self):
        x0, x1, x2, gs, y, y_zeta, b_ij, t_ij, e_hat, s_hat = self._build_consistent_case(0)
        with self.assertRaises(BinaryEquationError):
            verify_binary_relation_equations_38_45(
                (x0, x0, x2), gs, y, y_zeta, b_ij, t_ij, e_hat, s_hat, row=0, column=0,
            )

    def test_rejects_wrong_transcript_count(self):
        x0, x1, x2, gs, y, y_zeta, b_ij, t_ij, e_hat, s_hat = self._build_consistent_case(0)
        with self.assertRaises(BinaryEquationError):
            verify_binary_relation_equations_38_45(
                (x0, x1), gs[:2], y, y_zeta, b_ij, t_ij, e_hat, s_hat, row=0, column=0,
            )


if __name__ == "__main__":
    unittest.main()
