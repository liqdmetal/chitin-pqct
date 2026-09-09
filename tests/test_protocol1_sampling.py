import unittest
from decimal import Decimal

from pqct.protocol1_sampling import (
    FiniteDiscreteGaussian,
    Protocol1DistributionParameters,
    RejectionPolicy,
    SamplingError,
    XofByteSource,
    accept_rejection,
    build_rejection_plan,
    coefficient_vector,
    rejection_log_probability,
    sample_protocol1_masks,
)
from pqct.ring_commitment import ToyParameters


class Protocol1SamplingTests(unittest.TestCase):
    def test_gaussian_is_reproducible_and_tail_is_explicit(self):
        profile = FiniteDiscreteGaussian(Decimal("2.0"), 12)
        first = [profile.sample(XofByteSource(b"seed")) for _ in range(3)]
        second = [profile.sample(XofByteSource(b"seed")) for _ in range(3)]
        self.assertEqual(first, second)
        self.assertLess(profile.omitted_tail_bound, 1e-7)

    def test_protocol_formulas_and_mask_dimensions(self):
        params = ToyParameters(n=8, q=12289, k=2)
        masks = sample_protocol1_masks(
            XofByteSource(b"masks"), params, vector_count=2, bit_width=3,
            randomness_width=2, p=2, w=2,
            distribution=Protocol1DistributionParameters(B=1, gaussian_tail=8),
        )
        self.assertEqual(len(masks.r_e), 2)
        self.assertEqual(len(masks.r_f), 2)
        self.assertEqual(len(masks.t), 2)
        self.assertEqual([len(row) for row in masks.t], [3, 3])
        self.assertEqual([len(row) for row in masks.r_t], [2, 2])
        self.assertGreater(masks.t1, 0)
        self.assertGreater(masks.t2, 0)
        self.assertEqual(len(coefficient_vector(masks.r_f)), params.n * 2)

    def test_rejection_policy_never_exceeds_one(self):
        policy = RejectionPolicy(Decimal("4"), Decimal("3"), Decimal("8"))
        log_probability = rejection_log_probability((1, 2), (1, 1), policy)
        self.assertLessEqual(log_probability, 0)
        accepted, probability = accept_rejection(
            XofByteSource(b"reject"), (1, 2), (1, 1), policy,
        )
        self.assertGreaterEqual(probability, 0)
        self.assertLessEqual(probability, 1)
        self.assertIsInstance(accepted, bool)

    def test_out_of_bound_response_rejects(self):
        policy = RejectionPolicy(Decimal("4"), Decimal("1"), Decimal("2"))
        accepted, probability = accept_rejection(
            XofByteSource(b"reject"), (3, 0), (1, 0), policy,
        )
        self.assertFalse(accepted)
        self.assertEqual(probability, 0)

    def test_two_stage_rejection_plan_is_deterministic(self):
        ring = ToyParameters(n=8, q=12289, k=2)
        dist = Protocol1DistributionParameters(B=1, gaussian_tail=8)
        masks1 = sample_protocol1_masks(XofByteSource(b"plan-masks"), ring, 2, 3, 2, 2, 2, dist)
        masks2 = sample_protocol1_masks(XofByteSource(b"plan-masks"), ring, 2, 3, 2, 2, 2, dist)
        plan1 = build_rejection_plan(
            XofByteSource(b"plan-decision"), masks1, (2, -2, 0, 0, 0, 0, 0, 0),
            ((0, 1, 0), (1, 0, 0)),
            ((1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             (0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
            dist,
        )
        plan2 = build_rejection_plan(
            XofByteSource(b"plan-decision"), masks2, (2, -2, 0, 0, 0, 0, 0, 0),
            ((0, 1, 0), (1, 0, 0)),
            ((1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             (0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
            dist,
        )
        self.assertEqual(plan1, plan2)
        self.assertLessEqual(plan1.first[1], 1)
        self.assertLessEqual(plan1.second[1], 1)
        self.assertLessEqual(plan1.probability, 1)

    def test_invalid_parameters_rejected(self):
        with self.assertRaises(SamplingError):
            RejectionPolicy(Decimal("0"), Decimal("1"), Decimal("1"))

    def test_tail_for_sigma_scales_with_sigma(self):
        from pqct.protocol1_sampling import ZK_TAIL_SIGMAS, tail_for_sigma
        small = tail_for_sigma(Decimal("2"))
        large = tail_for_sigma(Decimal("20"))
        self.assertGreaterEqual(small, 8)
        # Default is the ZK-grade tail, not the old 6. Pin it via the
        # constant so the test tracks the shipped value.
        self.assertEqual(large, 20 * ZK_TAIL_SIGMAS)
        self.assertEqual(ZK_TAIL_SIGMAS, 13)
        with self.assertRaises(SamplingError):
            tail_for_sigma(Decimal(0))

    def test_bisect_sampler_matches_linear_scan(self):
        """The O(log n) sampler must be byte-identical to the linear CDF scan
        it replaced, for the same seed stream, at the ZK tail."""
        from pqct.protocol1_sampling import (
            FiniteDiscreteGaussian, XofByteSource, _uniform_unit, tail_for_sigma,
        )

        def linear(g, source):
            target = _uniform_unit(source) * g.total_weight
            running = Decimal(0)
            for value, weight in zip(g.support, g.weights):
                running += weight
                if target < running:
                    return value
            return g.support[-1]

        for sigma in (Decimal(1), Decimal(15), Decimal(120)):
            g = FiniteDiscreteGaussian(sigma, tail_for_sigma(sigma))
            for i in range(64):
                seed = b"bisect" + i.to_bytes(2, "big")
                self.assertEqual(
                    g.sample(XofByteSource(seed)), linear(g, XofByteSource(seed))
                )

    def test_auto_tail_gives_per_profile_support(self):
        from pqct.protocol1_sampling import Protocol1DistributionParameters
        manual = Protocol1DistributionParameters(
            B=1, gaussian_tail=12, phi1=Decimal("1"), phi2=Decimal("4"),
        )
        auto = Protocol1DistributionParameters(
            B=1, gaussian_tail=12, phi1=Decimal("1"), phi2=Decimal("4"),
            auto_tail=True,
        )
        m_t, m_open, _, _ = manual.profiles(2, 2, 3, 1, 8)
        a_t, a_open, _, _ = auto.profiles(2, 2, 3, 1, 8)
        # Manual: both profiles share tail 12 regardless of sigma.
        self.assertEqual(m_t.tail, 12)
        self.assertEqual(m_open.tail, 12)
        # Auto: opening profile (phi2*t2 larger sigma) gets a wider tail.
        self.assertGreater(a_open.tail, a_t.tail)
        self.assertGreater(a_open.sigma, a_t.sigma)


if __name__ == "__main__":
    unittest.main()
