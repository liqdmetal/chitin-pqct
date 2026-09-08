import unittest

from pqct.lattice_estimate import LatticeEstimateError
from pqct.lattice_estimate import beta_from_delta
from pqct.lattice_estimate import core_svp_bits
from pqct.lattice_estimate import delta_from_beta
from pqct.lattice_estimate import estimate_sis_hardness


class LatticeEstimateTests(unittest.TestCase):
    def test_delta_beta_round_trip(self):
        for beta in (60, 100, 200, 400, 800, 1600):
            delta = delta_from_beta(beta)
            recovered = beta_from_delta(delta)
            self.assertAlmostEqual(recovered, beta, delta=0.5)

    def test_delta_decreases_as_beta_increases(self):
        self.assertGreater(delta_from_beta(60), delta_from_beta(200))
        self.assertGreater(delta_from_beta(200), delta_from_beta(800))

    def test_core_svp_bits_ordering(self):
        classical = core_svp_bits(400, model="classical")
        quantum = core_svp_bits(400, model="quantum")
        paranoid = core_svp_bits(400, model="paranoid")
        self.assertGreater(classical, quantum)
        self.assertGreater(quantum, paranoid)

    def test_invalid_model_rejected(self):
        with self.assertRaises(LatticeEstimateError):
            core_svp_bits(400, model="bogus")

    def test_beta_from_delta_rejects_below_domain(self):
        with self.assertRaises(LatticeEstimateError):
            beta_from_delta(1.2)

    def test_estimate_sis_hardness_toy_candidates_are_finite(self):
        for n, d, q, bound in ((32, 32, 12289, 256), (64, 64, 786433, 1024)):
            estimate = estimate_sis_hardness(n, d, q, bound)
            self.assertGreater(estimate.classical_bits, 0)
            self.assertGreater(estimate.quantum_bits, 0)
            self.assertGreater(estimate.paranoid_bits, 0)
            self.assertGreater(estimate.classical_bits, estimate.quantum_bits)
            self.assertGreater(estimate.quantum_bits, estimate.paranoid_bits)

    def test_invalid_estimate_inputs_rejected(self):
        with self.assertRaises(LatticeEstimateError):
            estimate_sis_hardness(0, 32, 12289, 256)
        with self.assertRaises(LatticeEstimateError):
            estimate_sis_hardness(32, 32, 12289, 0)


if __name__ == "__main__":
    unittest.main()
