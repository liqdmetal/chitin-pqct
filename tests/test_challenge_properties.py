import unittest

from pqct.challenge import sample_sparse_challenge
from pqct.ring_commitment import ToyParameters


class ChallengePropertyTests(unittest.TestCase):
    def test_many_seeds_satisfy_paper_shape(self):
        params = ToyParameters(n=32, q=12289, k=1)
        for counter in range(100):
            challenge = sample_sparse_challenge(f"seed-{counter}".encode(), params, 8, 4)
            self.assertEqual(challenge.positions[-1], 31)
            self.assertEqual(challenge.hamming_weight, 8)
            self.assertEqual(set(abs(value) for value in challenge.coefficients), {4})


if __name__ == "__main__":
    unittest.main()
