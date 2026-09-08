import unittest

from pqct import (
    Matrix,
    RingElement,
    ToyParameters,
    Vector,
    commit,
    hash_transcript,
    open_commitment,
    verify_opening,
)
from pqct.ring_commitment import EncodingError, Opening


class RingCommitmentTests(unittest.TestCase):
    def setUp(self):
        self.p = ToyParameters(n=4, q=17, k=2)
        r = lambda values: RingElement.from_coeffs(values, self.p)
        self.matrix = Matrix(
            (
                (r((1, 2, 0, 1)), r((0, 1, 3, 0))),
                (r((2, 0, 1, 1)), r((1, 1, 0, 2))),
            ),
            self.p,
        )
        self.generator = Vector((r((1, 0, 0, 0)), r((0, 1, 0, 0))), self.p)
        self.randomness = Vector((r((3, 1, 0, 2)), r((4, 0, 1, 1))), self.p)
        self.message = r((5, 0, 0, 0))

    def test_opening_round_trip(self):
        commitment, opening = open_commitment(
            self.matrix, self.randomness, self.message, self.generator
        )
        self.assertTrue(verify_opening(commitment, opening, self.matrix, self.generator))

    def test_wrong_message_rejected(self):
        commitment, opening = open_commitment(
            self.matrix, self.randomness, self.message, self.generator
        )
        wrong = Opening(opening.randomness, RingElement.from_coeffs((6, 0, 0, 0), self.p))
        self.assertFalse(verify_opening(commitment, wrong, self.matrix, self.generator))

    def test_homomorphic_addition(self):
        second_randomness = Vector(
            (RingElement.from_coeffs((1, 2, 1, 0), self.p), RingElement.from_coeffs((0, 1, 1, 3), self.p)),
            self.p,
        )
        second_message = RingElement.from_coeffs((2, 0, 0, 0), self.p)
        first = commit(self.matrix, self.randomness, self.message, self.generator)
        second = commit(self.matrix, second_randomness, second_message, self.generator)
        combined = first.add(second)
        expected = commit(
            self.matrix,
            self.randomness.add(second_randomness),
            self.message.add(second_message),
            self.generator,
        )
        self.assertEqual(combined, expected)

    def test_negacyclic_wraparound(self):
        a = RingElement.from_coeffs((0, 0, 0, 1), self.p)
        b = RingElement.from_coeffs((0, 1, 0, 0), self.p)
        product = a.mul(b)
        self.assertEqual(product, RingElement.from_coeffs((-1, 0, 0, 0), self.p))

    def test_canonical_and_dimension_rejection(self):
        with self.assertRaises(EncodingError):
            RingElement((0, 1), self.p)
        with self.assertRaises(EncodingError):
            RingElement((0, 1, 2, self.p.q), self.p)
        with self.assertRaises(EncodingError):
            Vector((RingElement.zero(self.p),), self.p)

    def test_transcript_is_domain_and_length_delimited(self):
        a = hash_transcript(b"opening", b"ab", b"c")
        b = hash_transcript(b"opening", b"a", b"bc")
        c = hash_transcript(b"other", b"ab", b"c")
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, c)


if __name__ == "__main__":
    unittest.main()
