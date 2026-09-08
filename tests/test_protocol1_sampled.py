import unittest

from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.protocol1_sampled import SampledProtocol1Error, prove_protocol1_ring_sampled
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.ring_commitment import ToyParameters


class SampledProtocol1Tests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        self.base = HMCKey(
            G_r=((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
            G_m=((r((1, 0, 0, 0, 0, 0, 0, 0)), r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=self.params,
        )
        self.e = HMCKey(
            G_r=((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
            G_m=(tuple(r((1, 0, 0, 0, 0, 0, 0, 0)) for _ in range(4)),),
            params=self.params,
        )
        self.f = self.e
        self.g = HMCKey(
            G_r=((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
            G_m=((r((1, 0, 0, 0, 0, 0, 0, 0)), r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=self.params,
        )
        self.bits = (
            (r((0, 0, 0, 0, 0, 0, 0, 0)), r((1, 0, 0, 0, 0, 0, 0, 0))),
            (r((1, 0, 0, 0, 0, 0, 0, 0)), r((0, 0, 0, 0, 0, 0, 0, 0))),
        )
        self.openings = ((r((2, 0, 0, 0, 0, 0, 0, 0)),), (r((3, 0, 0, 0, 0, 0, 0, 0)),))
        self.commitments = tuple(self.base.commit(vector, opening) for vector, opening in zip(self.bits, self.openings))
        self.proof_params = RingProtocol1Parameters.from_paper_bounds(
            challenge_weight=2, challenge_coefficient_bound=1,
            B=1, p=1, k=2, m=1, d=8,
            phi1=2, phi2=8,
        )
        self.distribution = Protocol1DistributionParameters(
            B=1, gaussian_tail=8, phi1=1, phi2=2,
        )
    def test_sampled_wrapper_is_reproducible_when_it_accepts(self):
        first = prove_protocol1_ring_sampled(
            b"sampled-seed", b"sampled-statement", self.base, self.e, self.f, self.g,
            self.commitments, self.bits, self.openings, 1, 2,
            self.distribution, self.proof_params, max_attempts=512,
        )
        second = prove_protocol1_ring_sampled(
            b"sampled-seed", b"sampled-statement", self.base, self.e, self.f, self.g,
            self.commitments, self.bits, self.openings, 1, 2,
            self.distribution, self.proof_params, max_attempts=512,
        )
        self.assertEqual(first, second)
        self.assertTrue(first.rejection.accepted)
        self.assertGreaterEqual(first.attempts, 1)

    def test_zero_attempt_budget_is_rejected(self):
        with self.assertRaises(SampledProtocol1Error):
            prove_protocol1_ring_sampled(
                b"seed", b"statement", self.base, self.e, self.f, self.g,
                self.commitments, self.bits, self.openings, 1, 1,
                self.distribution, self.proof_params, max_attempts=0,
            )


if __name__ == "__main__":
    unittest.main()
