import unittest

from pqct.hmc import HMCKey, bounded_ring_element
from pqct.hmc_binding_experiment import search_relaxed_collisions
from pqct.ring_commitment import ToyParameters


class HMCBindingExperimentTests(unittest.TestCase):
    def test_zero_relaxation_finds_nonzero_collision(self):
        params = ToyParameters(n=2, q=17, k=1)
        r = lambda values: bounded_ring_element(values, params)
        one = r((1, 0))
        key = HMCKey(((one,),), ((one,),), params)
        result = search_relaxed_collisions(key, r((0, 0)), 1, 1, max_collisions=1)
        self.assertFalse(result.binding_holds_in_box)
        self.assertEqual(len(result.collisions), 1)

    def test_identity_key_has_no_small_collision(self):
        params = ToyParameters(n=2, q=17, k=1)
        r = lambda values: bounded_ring_element(values, params)
        one = r((1, 0))
        generator_three = r((3, 0))
        key = HMCKey(((one,),), ((generator_three,),), params)
        result = search_relaxed_collisions(key, one, 1, 1, max_collisions=1)
        self.assertTrue(result.binding_holds_in_box)
        self.assertGreater(result.checked, 0)


if __name__ == "__main__":
    unittest.main()
