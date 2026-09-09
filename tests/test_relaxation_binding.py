"""Tests for binding under relaxation.

The mechanical test builds a REAL inconsistent triple (the spliced adversary
from special_soundness), extracts two relaxed openings of the same
commitment, clears both relaxations, and measures the collision vector.
It must fit within the paper's 4p^2 accounting -- otherwise Step 2 of
special-soundness would not deliver a usable M-SIS solution.
"""

from __future__ import annotations

import unittest

from pqct.relaxation_binding import (
    assessment,
    collision_norm_from_relaxed_openings,
    inf_norm,
    paper_scale_accounting,
    relaxation_bound,
)
from pqct.ring_commitment import ToyParameters
from pqct.special_soundness import (
    honest_transcripts,
    three_challenges,
    toy_fixture,
)


class StructuralTests(unittest.TestCase):
    def test_relaxation_inf_norm_bounded_by_2p(self):
        rb = relaxation_bound(ToyParameters(n=8, q=12289, k=1), 4, 2, samples=48)
        self.assertLessEqual(rb.max_y_inf, 2 * 2)
        self.assertTrue(rb.within_structural)

    def test_relaxation_bound_is_tight_somewhere(self):
        """|y| = 2p is achievable (x_i has +p where x_j has -p), so the
        bound is not slack: the max seen should reach it on enough samples."""
        rb = relaxation_bound(ToyParameters(n=8, q=12289, k=1), 4, 2, samples=48)
        self.assertEqual(rb.max_y_inf, 2 * 2)

    def test_larger_peak_scales_bound(self):
        rb = relaxation_bound(ToyParameters(n=8, q=12289, k=1), 4, 3, samples=48)
        self.assertLessEqual(rb.max_y_inf, 6)


class PaperAccountingTests(unittest.TestCase):
    def test_gamma_bin_leading_factor_is_two_relaxations(self):
        """4p^2 == (2p)^2. This is the whole discharge: the paper priced the
        relaxation in already."""
        a = paper_scale_accounting(peak_p=8)
        self.assertEqual(a["gamma_bin_leading_factor"], 256)
        self.assertEqual(a["two_relaxation_factors_2p_squared"], 256)
        self.assertTrue(a["factors_match"])

    def test_holds_for_any_peak(self):
        for p in (2, 4, 8, 16):
            self.assertTrue(paper_scale_accounting(peak_p=p)["factors_match"])


class MechanicalCollisionTests(unittest.TestCase):
    """Build a real inconsistent pair of relaxed openings and measure."""

    def setUp(self):
        self.fx = toy_fixture()
        self.xs = three_challenges(self.fx)
        self.honest = honest_transcripts(self.fx, self.xs)
        # A second, different witness whose transcript we splice in.
        other_bits = (
            (self.fx.r((1, 0, 0, 0, 0, 0, 0, 0)), self.fx.r((1, 0, 0, 0, 0, 0, 0, 0))),
            (self.fx.r((1, 0, 0, 0, 0, 0, 0, 0)), self.fx.r((0, 0, 0, 0, 0, 0, 0, 0))),
        )
        self.other = honest_transcripts(toy_fixture(bits=other_bits), self.xs)

    def _relaxed_opening(self, pa, pb, xa, xb):
        """d = g^(a)-g^(b) flattened, r = z_b^(a)-z_b^(b), y = x_a - x_b."""
        d = tuple(
            ga.sub(gb)
            for ra, rb_ in zip(pa.responses_g, pb.responses_g)
            for ga, gb in zip(ra, rb_)
        )
        r = tuple(a.sub(b) for a, b in zip(pa.response_zb, pb.response_zb))
        return xa.sub(xb), d, r

    def test_consistent_openings_collide_to_zero(self):
        """Honest triple: clearing relaxations on two openings of the SAME
        commitment gives the zero vector -- no collision, as expected."""
        y01, d01, r01 = self._relaxed_opening(self.honest[0], self.honest[1], self.xs[0], self.xs[1])
        y12, d12, r12 = self._relaxed_opening(self.honest[1], self.honest[2], self.xs[1], self.xs[2])
        c = collision_norm_from_relaxed_openings(y01, y12, d01, r01, d12, r12)
        self.assertEqual(c.collision_inf, 0)

    def test_inconsistent_openings_give_short_nonzero_collision(self):
        """Spliced triple: two openings disagree. The cleared collision
        vector must be NONZERO (it is a real M-SIS solution) and SHORT
        (inflation within the paper's 4p^2 accounting)."""
        spliced = (self.honest[0], self.honest[1], self.other[2])
        y01, d01, r01 = self._relaxed_opening(spliced[0], spliced[1], self.xs[0], self.xs[1])
        y12, d12, r12 = self._relaxed_opening(spliced[1], spliced[2], self.xs[1], self.xs[2])
        c = collision_norm_from_relaxed_openings(y01, y12, d01, r01, d12, r12)
        self.assertGreater(c.collision_inf, 0, "a real collision must be nonzero")
        # p=2 for the toy challenges in three_challenges (entries in {0,1,2})
        self.assertTrue(
            c.within_paper_accounting(peak_p=2),
            f"inflation {c.inflation_factor:.1f}x exceeds 4p^2={c.paper_factor(2)}",
        )

    def test_inflation_is_reported_not_hidden(self):
        """The collision norm is reported raw. NOTE: it can come out BELOW
        the honest opening norm (0.3x observed) because the two y*d terms
        partially CANCEL -- the collision is a difference of two products.
        That is fine and even favourable (shorter = more clearly within
        the binding bound). What must never happen is inflation ABOVE the
        paper's 4p^2, which the previous test pins. Here we only assert
        the figures are populated and the relaxation itself is nonzero."""
        spliced = (self.honest[0], self.honest[1], self.other[2])
        y01, d01, r01 = self._relaxed_opening(spliced[0], spliced[1], self.xs[0], self.xs[1])
        y12, d12, r12 = self._relaxed_opening(spliced[1], spliced[2], self.xs[1], self.xs[2])
        c = collision_norm_from_relaxed_openings(y01, y12, d01, r01, d12, r12)
        self.assertGreater(c.inflation_factor, 0.0)
        self.assertGreater(c.relaxation_inf, 0)
        self.assertLessEqual(c.inflation_factor, c.paper_factor(2))


class AssessmentTests(unittest.TestCase):
    def test_discharged_with_caveats(self):
        s = assessment()["status"]
        self.assertIn("DISCHARGED", s)
        self.assertIn("computational", s)
        self.assertIn("Toy ring", s)


if __name__ == "__main__":
    unittest.main()
