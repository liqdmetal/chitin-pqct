import unittest

from pqct.challenge import sample_sparse_challenge
from pqct.ring_challenge import RingChallengeParameters, challenge_ring_element, derive_ring_challenge
from pqct.ring_commitment import RingElement, ToyParameters


class RingChallengeTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=2)
        self.cp = RingChallengeParameters(weight=3, coefficient_bound=5)
        z = RingElement.zero(self.params)
        self.commitments = ((z, z), (z,))

    def test_deterministic_and_full_transcript_bound(self):
        first = derive_ring_challenge(b"statement-a", self.params, self.cp, self.commitments)
        second = derive_ring_challenge(b"statement-a", self.params, self.cp, self.commitments)
        other = derive_ring_challenge(b"statement-b", self.params, self.cp, self.commitments)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertEqual(first.weight, 3)
        self.assertEqual(first.positions[-1], self.params.n - 1)
        self.assertTrue(all(abs(value) == 5 for value in first.coefficients))

    def test_canonical_ring_conversion(self):
        challenge = derive_ring_challenge(b"statement-a", self.params, self.cp, self.commitments)
        element = challenge_ring_element(challenge)
        self.assertEqual(element.params, self.params)
        self.assertEqual(sum(value != 0 for value in element.coeffs), 3)
        self.assertEqual(max(abs(value if value <= self.params.q // 2 else value - self.params.q) for value in element.coeffs), 5)

    def test_invalid_empty_statement(self):
        with self.assertRaises(ValueError):
            derive_ring_challenge(b"", self.params, self.cp, self.commitments)


if __name__ == "__main__":
    unittest.main()
