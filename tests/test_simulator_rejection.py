"""Tests for the SHVZK simulator rejection stage (Gao Lemma 6).

The substantive test is test_honest_rate_matches_lemma6_target: it measures
the HONEST prover's empirical acceptance rate and checks it against
1/mu(phi). That is a real check of Lemma 6 against this implementation --
if the honest rate does not converge to 1/mu, either the rejection exponent
or the sampler is wrong, and no amount of simulator work would fix it.
"""

import unittest
from decimal import Decimal

from pqct.protocol1_sampling import (
    FiniteDiscreteGaussian,
    RejectionPolicy,
    XofByteSource,
    accept_rejection,
    sample_gaussian_ring_vector,
)
from pqct.ring_commitment import ToyParameters
from pqct.simulator_rejection import (
    RejectionRateComparison,
    SimulatorRejectionError,
    measure_simulator_rate,
    simulate_rejection,
    simulator_acceptance_probability,
)


class SimulatorRateTests(unittest.TestCase):
    def setUp(self):
        self.policy = RejectionPolicy(phi=Decimal(8), T=Decimal(10))

    def test_target_rate_is_one_over_mu(self):
        probability = simulator_acceptance_probability(self.policy)
        self.assertAlmostEqual(
            float(probability), float(Decimal(1) / self.policy.mu), places=12
        )
        # mu > 1 always, so the rate is a genuine probability below 1.
        self.assertGreater(float(self.policy.mu), 1.0)
        self.assertLess(float(probability), 1.0)
        self.assertGreater(float(probability), 0.0)

    def test_rate_does_not_depend_on_any_witness(self):
        """Lemma 6's point: the accepted law is witness-independent, so the
        simulator's acceptance probability must be a function of phi alone."""
        same_phi = RejectionPolicy(phi=Decimal(8), T=Decimal(999))
        self.assertEqual(
            simulator_acceptance_probability(self.policy),
            simulator_acceptance_probability(same_phi),
        )

    def test_larger_phi_accepts_more_often(self):
        """mu(phi) -> 1 as phi grows, so acceptance -> 1."""
        rates = [
            float(simulator_acceptance_probability(
                RejectionPolicy(phi=Decimal(phi), T=Decimal(10))
            ))
            for phi in (1, 2, 4, 8, 16, 32)
        ]
        self.assertEqual(rates, sorted(rates), "rate must rise with phi")
        self.assertLess(rates[-1], 1.0)

    def test_empirical_simulator_rate_converges_to_target(self):
        attempts, accepts = measure_simulator_rate(b"sim-rate", self.policy, 4000)
        rate = accepts / attempts
        target = float(simulator_acceptance_probability(self.policy))
        self.assertAlmostEqual(rate, target, delta=0.03)

    def test_rejects_bad_sample_count(self):
        with self.assertRaises(SimulatorRejectionError):
            measure_simulator_rate(b"x", self.policy, 0)

    def test_decision_is_deterministic_per_seed(self):
        first = simulate_rejection(XofByteSource(b"seed-a"), self.policy)
        second = simulate_rejection(XofByteSource(b"seed-a"), self.policy)
        self.assertEqual(first.accepted, second.accepted)
        self.assertEqual(first.draw, second.draw)


class Lemma6HonestRateTests(unittest.TestCase):
    """Measure the HONEST prover's rate against Lemma 6's 1/mu prediction."""

    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.phi = Decimal(8)
        self.T = Decimal(10)
        self.policy = RejectionPolicy(phi=self.phi, T=self.T)
        self.gamma = self.policy.gamma  # phi*T
        self.profile = FiniteDiscreteGaussian(
            self.gamma, int(6 * float(self.gamma)) + 1
        )

    def _honest_trial(self, index: int, shift_scale: int):
        """One honest Rej trial: y ~ D_gamma, z = y + c, run Rej(z, c)."""
        source = XofByteSource(b"honest|y|" + index.to_bytes(8, "big"))
        y = sample_gaussian_ring_vector(source, self.params, 1, self.profile)
        from pqct.hmc import centered_coefficients

        y_coeffs = list(centered_coefficients(y[0]))
        # A fixed, small shift c with ||c|| < T, as Lemma 6 requires.
        c = [shift_scale] + [0] * (len(y_coeffs) - 1)
        z = [a + b for a, b in zip(y_coeffs, c)]
        decision_source = XofByteSource(b"honest|rej|" + index.to_bytes(8, "big"))
        accepted, _ = accept_rejection(decision_source, z, c, self.policy)
        return accepted

    def test_honest_rate_matches_lemma6_target(self):
        """Rej accepts at ~1/mu(phi) for the honest prover too.

        This is the load-bearing empirical check on the rejection exponent.
        """
        samples = 3000
        accepts = sum(self._honest_trial(i, 1) for i in range(samples))
        honest_rate = accepts / samples
        target = float(Decimal(1) / self.policy.mu)
        self.assertAlmostEqual(honest_rate, target, delta=0.05)

    def test_honest_and_simulator_rates_agree(self):
        samples = 3000
        honest = sum(self._honest_trial(i, 1) for i in range(samples))
        sim_attempts, sim_accepts = measure_simulator_rate(
            b"cmp", self.policy, samples
        )
        comparison = RejectionRateComparison(
            honest_attempts=samples, honest_accepts=honest,
            simulator_attempts=sim_attempts, simulator_accepts=sim_accepts,
            target_rate=Decimal(1) / self.policy.mu,
        )
        self.assertTrue(
            comparison.within(Decimal("0.05")),
            f"rates diverge: {comparison.summary()}",
        )
        self.assertLess(float(comparison.rate_gap), 0.05)

    def test_shift_at_or_above_T_is_rejected_outright(self):
        """Lemma 6 requires ||c|| < T; at or beyond T the exponent is -inf."""
        source = XofByteSource(b"oob")
        z = [0] * 8
        c = [int(self.T)] + [0] * 7
        accepted, probability = accept_rejection(source, z, c, self.policy)
        self.assertFalse(accepted)
        self.assertEqual(probability, Decimal(0))

    def test_comparison_flags_a_rigged_simulator(self):
        """A simulator that never aborts must be detected as divergent --
        this is the exact defect the rejection stage fixes."""
        samples = 1000
        rigged = RejectionRateComparison(
            honest_attempts=samples, honest_accepts=int(samples * 0.94),
            simulator_attempts=samples, simulator_accepts=samples,  # 100%
            target_rate=Decimal(1) / self.policy.mu,
        )
        self.assertFalse(rigged.within(Decimal("0.02")))
        self.assertGreater(float(rigged.rate_gap), 0.02)


if __name__ == "__main__":
    unittest.main()
