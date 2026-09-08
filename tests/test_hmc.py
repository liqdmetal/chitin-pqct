import unittest

from pqct.hmc import HMCError, HMCKey, bounded_ring_element, verify_opening, verify_relaxed_opening
from pqct.ring_commitment import RingElement, ToyParameters


class HMCTests(unittest.TestCase):
    def setUp(self):
        self.p = ToyParameters(n=4, q=17, k=2)
        r = lambda values: bounded_ring_element(values, self.p)
        self.key = HMCKey(
            G_r=((r((1, 0, 1, 0)), r((0, 1, 0, 1))), (r((2, 1, 0, 0)), r((0, 0, 1, 2)))),
            G_m=((r((1, 1, 0, 0)), r((0, 1, 1, 0))), (r((1, 0, 0, 1)), r((2, 0, 1, 0)))),
            params=self.p,
        )
        self.message = (r((1, 0, 0, 0)), r((0, 1, 0, 0)))
        self.randomness = (r((2, 0, 1, 0)), r((0, 1, 0, 2)))
        self.commitment = self.key.commit(self.message, self.randomness)

    def test_hmc_opening_round_trip(self):
        self.assertTrue(verify_opening(self.key, self.commitment, self.message, self.randomness))

    def test_public_commitment_does_not_recompute_tampered_opening(self):
        wrong = (self.randomness[0], bounded_ring_element((1, 1, 0, 2), self.p))
        self.assertFalse(verify_opening(self.key, self.commitment, self.message, wrong))

    def test_additive_homomorphism(self):
        second_message = (bounded_ring_element((2, 0, 0, 0), self.p), bounded_ring_element((0, 0, 1, 0), self.p))
        second_randomness = (bounded_ring_element((1, 1, 0, 0), self.p), bounded_ring_element((0, 2, 0, 1), self.p))
        combined = tuple(a.add(b) for a, b in zip(self.commitment, self.key.commit(second_message, second_randomness)))
        expected_message = tuple(a.add(b) for a, b in zip(self.message, second_message))
        expected_randomness = tuple(a.add(b) for a, b in zip(self.randomness, second_randomness))
        self.assertEqual(combined, self.key.commit(expected_message, expected_randomness))

    def test_relaxed_opening_boundary(self):
        scalar = bounded_ring_element((2, 0, 0, 0), self.p)
        scaled_message = tuple(scalar.mul(element) for element in self.message)
        scaled_randomness = tuple(scalar.mul(element) for element in self.randomness)
        self.assertTrue(verify_relaxed_opening(self.key, self.commitment, scalar, scaled_message, scaled_randomness))

    def test_rejects_bad_dimensions(self):
        with self.assertRaises(HMCError):
            self.key.commit(self.message[:1], self.randomness)


if __name__ == "__main__":
    unittest.main()
