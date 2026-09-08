import unittest

from pqct.binary_relation import (
    batch_linear_opening,
    build_binary_identity,
    verify_binary_identity,
)
from pqct.reduced_transcript import ToyVectorCommitmentKey


class BinaryRelationTests(unittest.TestCase):
    def test_binary_identity_holds_for_zero_and_one_bits(self):
        identity = build_binary_identity((0, 1, 1), (3, -2, 4), 7)
        self.assertTrue(verify_binary_identity(identity))
        self.assertEqual(identity.response, (3, 5, 11))

    def test_nonbinary_witness_is_rejected(self):
        with self.assertRaises(ValueError):
            build_binary_identity((0, 2), (1, 1), 3)

    def test_partial_amortized_opening_equation(self):
        key = ToyVectorCommitmentKey((3, 5, 7), 11, 12289)
        self.assertTrue(
            batch_linear_opening(
                key,
                bit_commitments=(key.commit((0, 1, 1), 7), key.commit((1, 0, 1), -3)),
                bits=((0, 1, 1), (1, 0, 1)),
                masks=((2, -1, 3), (-2, 4, 1)),
                bit_openings=(7, -3),
                mask_openings=(5, 2),
                weights=(2, -1),
                challenge=9,
            )
        )

    def test_tampered_opening_fails(self):
        key = ToyVectorCommitmentKey((3, 5, 7), 11, 12289)
        self.assertFalse(
            batch_linear_opening(
                key,
                bit_commitments=(key.commit((0, 1, 1), 7), key.commit((1, 0, 1), -3)),
                bits=((0, 1, 1), (1, 0, 1)),
                masks=((2, -1, 3), (-2, 4, 1)),
                bit_openings=(8, -3),
                mask_openings=(5, 2),
                weights=(2, -1),
                challenge=9,
            )
        )


if __name__ == "__main__":
    unittest.main()
