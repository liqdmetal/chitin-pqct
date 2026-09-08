import unittest

from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.protocol1_shvzk_compare import (
    SHVZKComparisonError,
    compare_fixed_challenge,
    encode_response_tuple,
)
from pqct.ring_commitment import ToyParameters


class Protocol1SHVZKComparisonTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        unit = r((1, 0, 0, 0, 0, 0, 0, 0))
        zero = r((0, 0, 0, 0, 0, 0, 0, 0))
        self.base = HMCKey(((unit,),), ((unit, r((0, 1, 0, 0, 0, 0, 0, 0))),), self.params)
        self.e = HMCKey(((unit,),), (tuple(unit for _ in range(4)),), self.params)
        self.f = self.e
        self.g = self.base
        self.bits = ((zero, unit), (unit, zero))
        self.openings = ((unit,), (r((2, 0, 0, 0, 0, 0, 0, 0)),))
        self.commitments = tuple(self.base.commit(bits, opening) for bits, opening in zip(self.bits, self.openings))
        self.distribution = Protocol1DistributionParameters(B=1, gaussian_tail=8, phi1=1, phi2=2)
        self.proof_params = RingProtocol1Parameters(2, 1, 1000000, 1000000, 1000000)
        self.zeta = r((1, 0, 0, 0, 0, 0, 0, 0))
        self.x = r((1, 0, 0, 0, 0, 0, 0, 0))

    def test_canonical_response_encoding_is_deterministic(self):
        from pqct.binary_protocol1_ring import build_protocol1_ring_transcript
        proof = build_protocol1_ring_transcript(
            b"s", self.base, self.e, self.f, self.g, self.commitments,
            self.bits, self.openings,
            ((self.x, self.x), (self.x, self.x)),
            (self.x,), (self.x,), ((self.x,), (self.x,)),
            self.proof_params, zeta=self.zeta, challenge_x=self.x,
        )
        self.assertEqual(encode_response_tuple(proof), encode_response_tuple(proof))
        self.assertNotEqual(encode_response_tuple(proof), b"")

    def test_fixed_challenge_comparison_is_reproducible(self):
        first = compare_fixed_challenge(
            b"compare", b"statement", self.base, self.e, self.f, self.g,
            self.commitments, self.bits, self.openings, 1, 2,
            self.distribution, self.proof_params, self.zeta, self.x, 12,
        )
        second = compare_fixed_challenge(
            b"compare", b"statement", self.base, self.e, self.f, self.g,
            self.commitments, self.bits, self.openings, 1, 2,
            self.distribution, self.proof_params, self.zeta, self.x, 12,
        )
        self.assertEqual(first, second)
        self.assertEqual(first.samples, 12)
        self.assertGreaterEqual(first.response_tv, 0)
        self.assertLessEqual(first.response_tv, 1)
        self.assertGreaterEqual(first.transcript_tv, 0)
        self.assertLessEqual(first.transcript_tv, 1)
        self.assertGreaterEqual(first.honest_rejection_rate, 0)
        self.assertGreaterEqual(first.simulator_rejection_rate, 0)
        self.assertIsNotNone(first.honest_mean_log_acceptance)
        self.assertIsNone(first.simulator_mean_log_acceptance)  # no simulator-side Rej gate exists
        self.assertIsNotNone(first.conditioned_response_tv)
        self.assertLessEqual(first.conditioned_response_tv, 1)

    def test_honest_mean_log_acceptance_excludes_rejected_samples(self):
        """Regression test: a rejected sample's forced-zero probability (log=-inf)
        must never be folded into the accepted-only mean log-acceptance stat.
        With enough samples at least one honest acceptance should occur, and the
        resulting mean must be finite (not -Infinity)."""
        result = compare_fixed_challenge(
            b"regression-seed", b"statement", self.base, self.e, self.f, self.g,
            self.commitments, self.bits, self.openings, 1, 2,
            self.distribution, self.proof_params, self.zeta, self.x, 256,
        )
        self.assertGreater(result.honest_accepts, 0)
        self.assertIsNotNone(result.honest_mean_log_acceptance)
        self.assertTrue(result.honest_mean_log_acceptance.is_finite())
        self.assertLessEqual(result.honest_mean_log_acceptance, 0)

    def test_invalid_sample_count_rejected(self):
        with self.assertRaises(SHVZKComparisonError):
            compare_fixed_challenge(
                b"s", b"statement", self.base, self.e, self.f, self.g,
                self.commitments, self.bits, self.openings, 1, 2,
                self.distribution, self.proof_params, self.zeta, self.x, 0,
            )


if __name__ == "__main__":
    unittest.main()
