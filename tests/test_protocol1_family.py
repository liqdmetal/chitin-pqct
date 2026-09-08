import unittest

from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.protocol1_family import (
    FamilyError,
    build_second_layer_family,
    build_two_layer_extraction_tree,
    extract_checked_second_layer,
)
from pqct.ring_commitment import ToyParameters


class Protocol1FamilyTests(unittest.TestCase):
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

    def test_family_has_three_shared_commitments_and_extracts(self):
        family = build_second_layer_family(
            b"family", self.base, self.e, self.f, self.g, self.commitments,
            self.bits, self.openings, self.masks, self.re, self.rf, self.rt,
            self.zetas[0], self.xs, self.challenge_params,
        )
        self.assertEqual(len(family.proofs), 3)
        self.assertTrue(all(audit.ok for audit in family.audits))
        extracted = extract_checked_second_layer(
            family, self.base, self.e, self.f, self.g, self.commitments,
        )
        self.assertEqual(extracted.first_delta, self.xs[0].sub(self.xs[1]))

    def test_full_two_layer_tree(self):
        tree = build_two_layer_extraction_tree(
            b"tree", self.base, self.e, self.f, self.g, self.commitments,
            self.bits, self.openings, self.masks, self.re, self.rf, self.rt,
            self.zetas, self.xs, self.challenge_params,
        )
        self.assertEqual(len(tree.branches), 2)
        self.assertEqual(len(tree.second_layer), 2)
        self.assertEqual(tree.first_layer.relaxation, self.zetas[0].sub(self.zetas[1]))

    def test_duplicate_x_challenge_rejected(self):
        with self.assertRaises(FamilyError):
            build_second_layer_family(
                b"family", self.base, self.e, self.f, self.g, self.commitments,
                self.bits, self.openings, self.masks, self.re, self.rf, self.rt,
                self.zetas[0], (self.xs[0], self.xs[0], self.xs[2]), self.challenge_params,
            )

    def test_more_than_two_vectors_is_rejected(self):
        with self.assertRaises(FamilyError):
            build_two_layer_extraction_tree(
                b"tree", self.base, self.e, self.f, self.g,
                self.commitments + (self.commitments[0],),
                self.bits + (self.bits[0],),
                self.openings + (self.openings[0],),
                self.masks + (self.masks[0],), self.re, self.rf,
                self.rt + (self.rt[0],), self.zetas, self.xs,
                self.challenge_params,
            )

    def test_wraparound_boundary_is_reported(self):
        small_params = ToyParameters(n=8, q=17, k=1)
        r = lambda values: bounded_ring_element(values, small_params)
        base = HMCKey(((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
                      ((r((1, 0, 0, 0, 0, 0, 0, 0)), r((0, 1, 0, 0, 0, 0, 0, 0))),), small_params)
        key_e = HMCKey(((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
                        (tuple(r((1, 0, 0, 0, 0, 0, 0, 0)) for _ in range(4)),), small_params)
        bits = ((r((1, 0, 0, 0, 0, 0, 0, 0)), r((0, 0, 0, 0, 0, 0, 0, 0))),)
        openings = ((r((1, 0, 0, 0, 0, 0, 0, 0)),),)
        commitments = (base.commit(bits[0], openings[0]),)
        masks = ((r((8, 0, 0, 0, 0, 0, 0, 0)), r((0, 0, 0, 0, 0, 0, 0, 0))),)
        params = RingProtocol1Parameters(1, 1, 100000, 100000, 100000)
        with self.assertRaises(FamilyError):
            build_second_layer_family(
                b"wrap", base, key_e, key_e, base, commitments, bits, openings,
                masks, (r((1, 0, 0, 0, 0, 0, 0, 0)),),
                (r((1, 0, 0, 0, 0, 0, 0, 0)),),
                ((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
                r((1, 0, 0, 0, 0, 0, 0, 0)), self.xs, params,
            )


if __name__ == "__main__":
    unittest.main()
