import unittest
from decimal import Decimal, localcontext

from pqct.binary_protocol1_ring import (
    RingProtocol1Error,
    RingProtocol1Parameters,
    prove_protocol1_ring,
    verify_protocol1_ring,
)
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.ring_commitment import ToyParameters


class RingProtocol1Tests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        self.base = HMCKey(
            G_r=((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
            G_m=((r((1, 0, 0, 0, 0, 0, 0, 0)), r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=self.params,
        )
        # Protocol 1 E/F commit one ring element per bit; G commits one per bit-column.
        self.e = HMCKey(
            G_r=((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
            G_m=(tuple(r((1, 0, 0, 0, 0, 0, 0, 0)) for _ in range(4)),),
            params=self.params,
        )
        self.f = self.e
        self.g = HMCKey(
            G_r=((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
            G_m=((r((1, 0, 0, 0, 0, 0, 0, 0)), r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=self.params,
        )
        self.bits = (
            (r((0, 0, 0, 0, 0, 0, 0, 0)), r((1, 0, 0, 0, 0, 0, 0, 0))),
            (r((1, 0, 0, 0, 0, 0, 0, 0)), r((0, 0, 0, 0, 0, 0, 0, 0))),
        )
        self.openings = ((r((2, 0, 0, 0, 0, 0, 0, 0)),), (r((3, 0, 0, 0, 0, 0, 0, 0)),))
        self.commitments = tuple(self.base.commit(vector, opening) for vector, opening in zip(self.bits, self.openings))
        self.masks = (
            (r((1, 0, 0, 0, 0, 0, 0, 0)), r((2, 0, 0, 0, 0, 0, 0, 0))),
            (r((3, 0, 0, 0, 0, 0, 0, 0)), r((4, 0, 0, 0, 0, 0, 0, 0))),
        )
        self.re = (r((1, 0, 0, 0, 0, 0, 0, 0)),)
        self.rf = (r((2, 0, 0, 0, 0, 0, 0, 0)),)
        self.rt = ((r((3, 0, 0, 0, 0, 0, 0, 0)),), (r((4, 0, 0, 0, 0, 0, 0, 0)),))
        self.proof_params = RingProtocol1Parameters(3, 5, 1000, 1000, 1000)

    def make_proof(self):
        return prove_protocol1_ring(
            b"ring-protocol1", self.base, self.e, self.f, self.g,
            self.commitments, self.bits, self.openings, self.masks,
            self.re, self.rf, self.rt, self.proof_params,
        )

    def test_honest_ring_equations_verify(self):
        proof = self.make_proof()
        self.assertTrue(verify_protocol1_ring(
            b"ring-protocol1", self.base, self.e, self.f, self.g,
            self.commitments, proof, self.proof_params,
        ))

    def test_statement_mutation_fails(self):
        self.assertFalse(verify_protocol1_ring(
            b"other", self.base, self.e, self.f, self.g,
            self.commitments, self.make_proof(), self.proof_params,
        ))

    def test_proof_commitment_mutation_fails(self):
        proof = self.make_proof()
        mutated = type(proof)(
            self.base.commit((self.r((1, 0, 0, 0, 0, 0, 0, 0)), self.r((0, 0, 0, 0, 0, 0, 0, 0))), self.re),
            proof.commitment_f, proof.commitment_g,
            proof.responses_g, proof.response_zg, proof.response_zb,
        )
        self.assertFalse(verify_protocol1_ring(
            b"ring-protocol1", self.base, self.e, self.f, self.g,
            self.commitments, mutated, self.proof_params,
        ))


class RingProtocol1BoundPolicyTests(unittest.TestCase):
    """Verifier-policy bounds are local config: malformed must fail predictably.

    An infinite bound silently defeats its own norm cap, and a NaN reaches the
    decimal comparison as InvalidOperation instead of a domain error. Both are
    configuration faults, so they must raise RingProtocol1Error.
    """

    BASE = dict(
        challenge_weight=1,
        challenge_coefficient_bound=1,
        g_bound=1,
        zg_bound=1,
        zb_bound=1,
    )

    def _build(self, **overrides):
        arguments = dict(self.BASE)
        arguments.update(overrides)
        return RingProtocol1Parameters(**arguments)

    def test_non_finite_bounds_are_rejected(self):
        for field in ("g_bound", "zg_bound", "zb_bound"):
            for value in (
                Decimal("Infinity"),
                Decimal("-Infinity"),
                Decimal("NaN"),
                Decimal("sNaN"),
            ):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(RingProtocol1Error):
                        self._build(**{field: value})

    def test_zero_negative_and_unconvertible_bounds_are_rejected(self):
        bad_values = (0, -1, Decimal(0), Decimal("-2.5"), None, "not-a-number")
        for field in ("g_bound", "zg_bound", "zb_bound"):
            for value in bad_values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(RingProtocol1Error):
                        self._build(**{field: value})

    def test_finite_positive_bounds_are_accepted(self):
        params = self._build(g_bound=1000, zg_bound=Decimal("1500.5"),
                             zb_bound=Decimal(2))
        self.assertEqual(Decimal(params.g_bound), Decimal(1000))
        self.assertEqual(Decimal(params.zg_bound), Decimal("1500.5"))
        self.assertEqual(Decimal(params.zb_bound), Decimal(2))

    def _paper(self, **overrides):
        arguments = dict(
            challenge_weight=3,
            challenge_coefficient_bound=5,
            B=2,
            p=3,
            k=1,
            m=2,
            d=2,
            phi1=Decimal("1.5"),
            phi2=Decimal("2.25"),
        )
        arguments.update(overrides)
        return RingProtocol1Parameters.from_paper_bounds(**arguments)

    def test_non_finite_phi_inputs_are_rejected_before_arithmetic(self):
        for field in ("phi1", "phi2"):
            for value in (Decimal("Infinity"), Decimal("-Infinity"),
                          Decimal("NaN"), Decimal("sNaN")):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(RingProtocol1Error):
                        self._paper(**{field: value})

    def test_zero_negative_or_unconvertible_phi_inputs_are_rejected(self):
        for field in ("phi1", "phi2"):
            for value in (Decimal(0), Decimal("-1"), 0, -1, None, "x"):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(RingProtocol1Error):
                        self._paper(**{field: value})

    def test_finite_paper_bounds_are_unchanged(self):
        # Captured from the unmodified 01d6a9d implementation at precision 28;
        # pin compatibility without reproducing the formulas under test.
        with localcontext() as context:
            context.prec = 28
            params = self._paper()
        self.assertEqual(params.g_bound, Decimal("31.17691453623979128349403415"))
        self.assertEqual(params.zg_bound, Decimal("561.1844616523162431028926146"))
        self.assertEqual(params.zb_bound, Decimal("11223.68923304632486205785229"))
        self.assertEqual(params.challenge_coefficient_bound, 5)


if __name__ == "__main__":
    unittest.main()
