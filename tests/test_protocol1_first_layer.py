import unittest

from pqct.protocol1_extraction import (
    ExtractionError,
    extract_first_layer_s2,
    validate_first_layer_relation,
)
from pqct.ring_commitment import RingElement, ToyParameters


class FirstLayerExtractionTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.r = lambda values: RingElement.from_coeffs(values, self.params)
        self.one = self.r((1, 0, 0, 0, 0, 0, 0, 0))
        self.two = self.one.add(self.one)
        self.three = self.two.add(self.one)
        self.four = self.three.add(self.one)
        self.zeta0 = self.one
        self.zeta1 = self.two
        self.b0 = (self.three,)
        self.b1 = (self.four,)
        self.r0 = (self.one,)
        self.r1 = (self.two,)
        # Accepted openings of y(B0 + zeta*B1) are represented by
        # b0 + zeta*b1 and the corresponding randomness.
        self.aggregate_messages = (
            (self.b0[0].add(self.zeta0.mul(self.b1[0])),),
            (self.b0[0].add(self.zeta1.mul(self.b1[0])),),
        )
        self.aggregate_randomness = (
            (self.r0[0].add(self.zeta0.mul(self.r1[0])),),
            (self.r0[0].add(self.zeta1.mul(self.r1[0])),),
        )

    def test_extracts_relaxed_openings_without_inverse(self):
        result = extract_first_layer_s2(
            (self.zeta0, self.zeta1),
            self.aggregate_messages,
            self.aggregate_randomness,
        )
        y = self.zeta0.sub(self.zeta1)
        self.assertEqual(result.relaxation, y)
        self.assertEqual(result.opening_b1.message[0], y.mul(self.b1[0]))
        self.assertEqual(result.opening_b1.randomness[0], self.aggregate_randomness[0][0].sub(self.aggregate_randomness[1][0]))
        self.assertEqual(result.opening_b0.message[0], y.mul(self.b0[0]))
        expected_r0 = self.zeta0.mul(self.aggregate_randomness[1][0]).sub(
            self.zeta1.mul(self.aggregate_randomness[0][0])
        )
        self.assertEqual(result.opening_b0.randomness[0], expected_r0)
        self.assertTrue(validate_first_layer_relation(
            result, self.zeta0, self.aggregate_messages[0], self.aggregate_randomness[0],
        ))
        self.assertTrue(validate_first_layer_relation(
            result, self.zeta1, self.aggregate_messages[1], self.aggregate_randomness[1],
        ))

    def test_tampered_aggregate_fails_relation_check(self):
        result = extract_first_layer_s2(
            (self.zeta0, self.zeta1),
            self.aggregate_messages,
            self.aggregate_randomness,
        )
        self.assertFalse(validate_first_layer_relation(
            result, self.zeta0,
            (self.aggregate_messages[0][0].add(self.one),),
            self.aggregate_randomness[0],
        ))

    def test_duplicate_challenges_rejected(self):
        with self.assertRaises(ExtractionError):
            extract_first_layer_s2(
                (self.zeta0, self.zeta0),
                self.aggregate_messages,
                self.aggregate_randomness,
            )

    def test_dimension_mutation_rejected(self):
        with self.assertRaises(ExtractionError):
            extract_first_layer_s2(
                (self.zeta0, self.zeta1),
                self.aggregate_messages,
                ((self.r0[0],), ()),
            )


if __name__ == "__main__":
    unittest.main()
