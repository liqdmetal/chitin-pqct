import unittest

from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.protocol1_binary_relation import BinaryRelationError
from pqct.protocol1_binary_relation import extract_binary_witness_row
from pqct.protocol1_family import build_second_layer_family
from pqct.ring_commitment import ToyParameters


class Protocol1BinaryRelationTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        unit = r((1, 0, 0, 0, 0, 0, 0, 0))
        x1 = r((1, 1, 0, 0, 0, 0, 0, 0))
        x2 = r((2, 0, 1, 0, 0, 0, 0, 0))
        x3 = r((3, 1, 1, 0, 0, 0, 0, 0))
        self.base = HMCKey(
            G_r=((unit,),),
            G_m=((unit, r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=self.params,
        )
        self.e = HMCKey(
            G_r=((unit,),),
            G_m=(tuple(unit for _ in range(4)),),
            params=self.params,
        )
        self.f = self.e
        self.g = self.base
        self.bits = (
            (r((0, 0, 0, 0, 0, 0, 0, 0)), unit),
            (unit, r((0, 0, 0, 0, 0, 0, 0, 0))),
        )
        self.openings = ((r((1, 0, 0, 0, 0, 0, 0, 0)),), (r((2, 0, 0, 0, 0, 0, 0, 0)),))
        self.commitments = tuple(
            self.base.commit(message, opening)
            for message, opening in zip(self.bits, self.openings)
        )
        self.masks = ((x1, x2), (x2, x3))
        self.re = (unit,)
        self.rf = (r((1, 0, 0, 0, 0, 0, 0, 0)),)
        self.rt = ((r((1, 0, 0, 0, 0, 0, 0, 0)),), (r((2, 0, 0, 0, 0, 0, 0, 0)),))
        self.challenge_params = RingProtocol1Parameters(3, 1, 100000, 100000, 100000)
        self.zetas = (unit, r((2, 0, 0, 0, 0, 0, 0, 0)))
        self.xs = (unit, r((2, 1, 0, 0, 0, 0, 0, 0)), r((3, 0, 1, 0, 0, 0, 0, 0)))

    def test_extracted_bit_matches_true_difference(self):
        family = build_second_layer_family(
            b"family", self.base, self.e, self.f, self.g, self.commitments,
            self.bits, self.openings, self.masks, self.re, self.rf, self.rt,
            self.zetas[0], self.xs, self.challenge_params,
        )
        row, column = 0, 1
        check = extract_binary_witness_row(
            family.proofs, family.challenges, row, column,
        )
        x0 = self.xs[0]
        x1 = self.xs[1]
        y = x0.sub(x1)
        # bits[0][1] = unit (the true bit at row=0,column=1); expect
        # relaxed_bit == y * 1 = y's own centered coefficients.
        from pqct.hmc import centered_coefficients
        self.assertEqual(check.relaxed_bit, centered_coefficients(y))
        self.assertEqual(check.row, row)
        self.assertEqual(check.column, column)

    def test_zero_bit_gives_zero_relaxed_value(self):
        family = build_second_layer_family(
            b"family", self.base, self.e, self.f, self.g, self.commitments,
            self.bits, self.openings, self.masks, self.re, self.rf, self.rt,
            self.zetas[0], self.xs, self.challenge_params,
        )
        check = extract_binary_witness_row(
            family.proofs, family.challenges, 0, 0,
        )
        zero_poly = tuple(0 for _ in range(self.params.n))
        self.assertEqual(check.relaxed_bit, zero_poly)

    def test_rejects_mismatched_challenge_count(self):
        with self.assertRaises(BinaryRelationError):
            extract_binary_witness_row((), (self.xs[0],), 0, 0)


if __name__ == "__main__":
    unittest.main()