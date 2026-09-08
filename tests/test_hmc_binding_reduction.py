import unittest

from pqct.hmc import HMCKey
from pqct.hmc import bounded_ring_element
from pqct.hmc import infinity_norm
from pqct.hmc_binding_reduction import BindingReductionError
from pqct.hmc_binding_reduction import check_binding_parameters
from pqct.hmc_binding_reduction import derive_msis_solution
from pqct.ring_commitment import ToyParameters


class HMCBindingReductionTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=2, q=17, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        self.one = r((1, 0))
        self.key = HMCKey(((self.one,),), ((self.one,),), self.params)

    def test_reduction_from_real_zero_relaxation_collision(self):
        # commit(m,r) = m + r for this degenerate 1x1 key (G_m=G_r=1).
        # (m0,r0)=(1,0) and (m1,r1)=(0,1) both commit to 1: a genuine
        # STRICT collision (G.z=0), which is what Gao's reduction
        # (paper lines 312-317) requires -- not a merely y-relaxed one.
        message0 = (self.one,)
        randomness0 = (self.r((0, 0)),)
        message1 = (self.r((0, 0)),)
        randomness1 = (self.one,)
        self.assertEqual(
            self.key.commit(message0, randomness0),
            self.key.commit(message1, randomness1),
        )
        instance = derive_msis_solution(
            self.key, self.one,
            message0, randomness0,
            message1, randomness1,
        )
        expected_beta = infinity_norm(
            (*instance.z_message, *instance.z_randomness)
        )
        self.assertEqual(instance.beta, expected_beta)
        self.assertGreater(instance.beta, 0)


    def test_non_collision_rejected(self):
        with self.assertRaises(BindingReductionError):
            derive_msis_solution(
                self.key, self.one,
                (self.one,), (self.one,),
                (self.one,), (self.one,),
            )

    def test_valid_witness_but_no_true_collision_rejected(self):
        two = self.r((2, 0))
        with self.assertRaises(BindingReductionError):
            derive_msis_solution(
                self.key, self.one,
                (self.one,), (self.one,),
                (two,), (self.one,),
            )

    def test_binding_equation_two_passes_with_small_beta(self):
        check = check_binding_parameters(
            n=32, d=32, q=12289, delta=1.0045, beta=100,
        )
        self.assertTrue(check.passes)

    def test_binding_equation_two_fails_with_huge_beta(self):
        check = check_binding_parameters(
            n=32, d=32, q=12289, delta=1.0045, beta=10**30,
        )
        self.assertFalse(check.passes)

    def test_invalid_delta_rejected(self):
        with self.assertRaises(BindingReductionError):
            check_binding_parameters(
                n=32, d=32, q=12289, delta=0.5, beta=100,
            )


if __name__ == "__main__":
    unittest.main()
