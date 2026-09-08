import unittest

from pqct.challenge import ChallengeError, sample_sparse_challenge
from pqct.ring_commitment import ToyParameters


class ChallengeTests(unittest.TestCase):
    def test_reproducible_sparse_challenge(self):
        params = ToyParameters(n=32, q=12289, k=2)
        first = sample_sparse_challenge(b"seed", params, 8, 4)
        second = sample_sparse_challenge(b"seed", params, 8, 4)
        other = sample_sparse_challenge(b"other", params, 8, 4)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertEqual(first.hamming_weight, 8)
        self.assertEqual(len(set(first.positions)), 8)
        self.assertEqual(first.positions[-1], params.n - 1)
        self.assertTrue(all(abs(value) == 4 for value in first.coefficients))

    def test_invalid_parameters_rejected(self):
        params = ToyParameters(n=4, q=17, k=2)
        with self.assertRaises(ChallengeError):
            sample_sparse_challenge(b"seed", params, 5, 1)
        with self.assertRaises(ChallengeError):
            sample_sparse_challenge(b"seed", params, 2, 9)


if __name__ == "__main__":
    unittest.main()
