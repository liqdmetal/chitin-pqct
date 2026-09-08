import unittest

from pqct.binary_protocol1_ring import (
    RingProtocol1Parameters,
    build_protocol1_ring_transcript,
    verify_protocol1_ring,
)
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.protocol1_independent_oracle import (
    RawHMCKey,
    build_independent_transcript,
    verify_independent_transcript,
)
from pqct.ring_commitment import ToyParameters


class CrossImplementationProtocol1Tests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        one = r((1, 0, 0, 0, 0, 0, 0, 0))
        zero = r((0, 0, 0, 0, 0, 0, 0, 0))
        self.base = HMCKey(((one,),), ((one, r((0, 1, 0, 0, 0, 0, 0, 0))),), self.params)
        self.e = HMCKey(((one,),), (tuple(one for _ in range(4)),), self.params)
        self.f = self.e
        self.g = self.base
        self.bits = ((zero, one), (one, zero))
        self.openings = ((r((1, 0, 0, 0, 0, 0, 0, 0)),), (r((2, 0, 0, 0, 0, 0, 0, 0)),))
        self.masks = (
            (r((1, 1, 0, 0, 0, 0, 0, 0)), r((2, 0, 1, 0, 0, 0, 0, 0))),
            (r((2, 0, 1, 0, 0, 0, 0, 0)), r((3, 1, 1, 0, 0, 0, 0, 0))),
        )
        self.re = (one,)
        self.rf = (one,)
        self.rt = ((one,), (r((2, 0, 0, 0, 0, 0, 0, 0)),))
        self.zeta = one
        self.x = r((2, 1, 0, 0, 0, 0, 0, 0))
        self.params_p1 = RingProtocol1Parameters(3, 1, 100000, 100000, 100000)

    def _raw_key(self, key):
        raw = lambda element: tuple(element.coeffs)
        return RawHMCKey(
            tuple(tuple(raw(value) for value in row) for row in key.G_r),
            tuple(tuple(raw(value) for value in row) for row in key.G_m),
            self.params.q,
        )

    def test_same_hand_constructed_vectors_cross_both_verifiers(self):
        commitments = tuple(self.base.commit(bits, opening) for bits, opening in zip(self.bits, self.openings))
        proof = build_protocol1_ring_transcript(
            b"cross", self.base, self.e, self.f, self.g, commitments,
            self.bits, self.openings, self.masks, self.re, self.rf, self.rt,
            self.params_p1, zeta=self.zeta, challenge_x=self.x,
        )
        self.assertTrue(verify_protocol1_ring(
            b"cross", self.base, self.e, self.f, self.g, commitments, proof,
            self.params_p1, zeta=self.zeta, challenge_x=self.x,
        ))
        raw_transcript = build_independent_transcript(
            self._raw_key(self.base), self._raw_key(self.e), self._raw_key(self.f),
            self._raw_key(self.g),
            tuple(tuple(tuple(value.coeffs) for value in row) for row in self.bits),
            tuple(tuple(tuple(value.coeffs) for value in row) for row in self.openings),
            tuple(tuple(tuple(value.coeffs) for value in row) for row in self.masks),
            tuple(tuple(value.coeffs) for value in self.re),
            tuple(tuple(value.coeffs) for value in self.rf),
            tuple(tuple(tuple(value.coeffs) for value in row) for row in self.rt),
            tuple(self.zeta.coeffs), tuple(self.x.coeffs),
        )
        self.assertTrue(verify_independent_transcript(
            self._raw_key(self.base), self._raw_key(self.e), self._raw_key(self.f),
            self._raw_key(self.g), raw_transcript,
        ))
        self.assertEqual(tuple(tuple(value.coeffs) for value in proof.commitment_e), raw_transcript.proof.commitment_e)
        self.assertEqual(tuple(tuple(value.coeffs) for value in proof.commitment_f), raw_transcript.proof.commitment_f)
        self.assertEqual(tuple(tuple(value.coeffs) for value in proof.commitment_g), raw_transcript.proof.commitment_g)
        self.assertEqual(
            tuple(tuple(value.coeffs for value in row) for row in proof.responses_g),
            raw_transcript.proof.responses_g,
        )
        self.assertEqual(tuple(value.coeffs for value in proof.response_zg), raw_transcript.proof.response_zg)
        self.assertEqual(tuple(value.coeffs for value in proof.response_zb), raw_transcript.proof.response_zb)

    def test_sign_swapped_raw_transcript_is_rejected(self):
        transcript = build_independent_transcript(
            self._raw_key(self.base), self._raw_key(self.e), self._raw_key(self.f), self._raw_key(self.g),
            tuple(tuple(tuple(value.coeffs) for value in row) for row in self.bits),
            tuple(tuple(tuple(value.coeffs) for value in row) for row in self.openings),
            tuple(tuple(tuple(value.coeffs) for value in row) for row in self.masks),
            tuple(tuple(value.coeffs) for value in self.re), tuple(tuple(value.coeffs) for value in self.rf),
            tuple(tuple(tuple(value.coeffs) for value in row) for row in self.rt),
            tuple(self.zeta.coeffs), tuple(self.x.coeffs),
        )
        proof = transcript.proof
        swapped = type(proof)(proof.commitment_e, proof.commitment_g, proof.commitment_f,
                              proof.responses_g, proof.response_zg, proof.response_zb)
        changed = type(transcript)(transcript.bit_commitments, swapped, transcript.zeta, transcript.x)
        self.assertFalse(verify_independent_transcript(
            self._raw_key(self.base), self._raw_key(self.e), self._raw_key(self.f), self._raw_key(self.g), changed,
        ))


if __name__ == "__main__":
    unittest.main()
