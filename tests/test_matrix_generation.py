import unittest

from pqct.matrix_generation import generate_hmc_key
from pqct.ring_commitment import ToyParameters


class MatrixGenerationTests(unittest.TestCase):
    def test_seeded_key_is_reproducible(self):
        params = ToyParameters(n=4, q=17, k=2)
        first = generate_hmc_key(b"seed", params, 2, 3, ring_rows=4)
        second = generate_hmc_key(b"seed", params, 2, 3, ring_rows=4)
        other = generate_hmc_key(b"other", params, 2, 3, ring_rows=4)
        self.assertEqual(first.encode(), second.encode())
        self.assertNotEqual(first.encode(), other.encode())

    def test_dimensions_and_canonical_coefficients(self):
        params = ToyParameters(n=4, q=17, k=2)
        key = generate_hmc_key(b"seed", params, 2, 3, ring_rows=4)
        self.assertEqual((key.ring_rows, key.randomness_width, key.message_width), (4, 2, 3))
        self.assertTrue(all(0 <= coefficient < params.q for matrix in (key.G_r, key.G_m) for row in matrix for element in row for coefficient in element.coeffs))


if __name__ == "__main__":
    unittest.main()
