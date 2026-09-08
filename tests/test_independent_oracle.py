import unittest

from pqct.hmc import HMCKey, bounded_ring_element
from pqct.independent_oracle import exhaustive_scalar_relations, matrix_commit, negacyclic_mul
from pqct.ring_commitment import ToyParameters


class IndependentOracleTests(unittest.TestCase):
    def test_negacyclic_product_matches_ring_path(self):
        params = ToyParameters(n=4, q=17, k=2)
        left = (1, 2, 3, 4)
        right = (2, 0, 1, 3)
        expected = bounded_ring_element(left, params).mul(bounded_ring_element(right, params)).coeffs
        self.assertEqual(negacyclic_mul(left, right, params.q), expected)

    def test_matrix_commit_matches_hmc_path(self):
        params = ToyParameters(n=2, q=17, k=1)
        r = lambda values: bounded_ring_element(values, params)
        key = HMCKey(
            G_r=((r((1, 0)),), (r((2, 1)),)),
            G_m=((r((3, 1)),), (r((1, 2)),)),
            params=params,
        )
        randomness = (r((4, 0)),)
        message = (r((1, 1)),)
        committed = key.commit(message, randomness)
        oracle = matrix_commit(
            (((1, 0),), ((2, 1),)),
            (((3, 1),), ((1, 2),)),
            ((4, 0),),
            ((1, 1),),
            params.q,
        )
        self.assertEqual(tuple(element.coeffs for element in committed), oracle)

    def test_exhaustive_relation_oracle(self):
        values = exhaustive_scalar_relations(3, 5)
        self.assertIn((0, 0, 0), values)
        self.assertTrue(all(sum((1 << i) * value for i, value in enumerate(row)) == 0 for row in values))


if __name__ == "__main__":
    unittest.main()
