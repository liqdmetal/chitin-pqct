import unittest

from pqct.protocol1_independent_oracle import (
    RawHMCKey,
    build_independent_transcript,
    verify_independent_transcript,
)


class IndependentProtocol1OracleTests(unittest.TestCase):
    def setUp(self):
        q = 12289
        n = 8
        zero = (0,) * n
        one = (1,) + (0,) * (n - 1)
        x1 = (1, 1, 0, 0, 0, 0, 0, 0)
        x2 = (2, 0, 1, 0, 0, 0, 0, 0)
        x3 = (3, 1, 1, 0, 0, 0, 0, 0)
        self.zero, self.one = zero, one
        self.base = RawHMCKey(
            G_r=(((one,),)),
            G_m=(((one, (0, 1, 0, 0, 0, 0, 0, 0))),),
            q=q,
        )
        self.e = RawHMCKey(
            G_r=(((one,),)),
            G_m=((one, one, one, one),),
            q=q,
        )
        self.f = self.e
        self.g = self.base
        self.bits = ((zero, one), (one, zero))
        self.openings = ((one,), ((2, 0, 0, 0, 0, 0, 0, 0),))
        self.masks = ((x1, x2), (x2, x3))
        self.re = (one,)
        self.rf = (one,)
        self.rt = ((one,), ((2, 0, 0, 0, 0, 0, 0, 0),))
        self.zeta = one
        self.x = (2, 1, 0, 0, 0, 0, 0, 0)

    def _transcript(self):
        return build_independent_transcript(
            self.base, self.e, self.f, self.g,
            self.bits, self.openings, self.masks,
            self.re, self.rf, self.rt, self.zeta, self.x,
        )

    def test_independent_oracle_accepts_hand_constructed_transcript(self):
        transcript = self._transcript()
        self.assertTrue(verify_independent_transcript(
            self.base, self.e, self.f, self.g, transcript,
        ))

    def test_response_mutation_is_rejected(self):
        transcript = self._transcript()
        proof = transcript.proof
        mutated = type(proof)(
            proof.commitment_e,
            proof.commitment_f,
            proof.commitment_g,
            proof.responses_g,
            (tuple((value + 1) % self.base.q for value in proof.response_zg[0]),),
            proof.response_zb,
        )
        changed = type(transcript)(
            transcript.bit_commitments, mutated, transcript.zeta, transcript.x,
        )
        self.assertFalse(verify_independent_transcript(
            self.base, self.e, self.f, self.g, changed,
        ))

    def test_challenge_mutation_is_rejected(self):
        transcript = self._transcript()
        changed = type(transcript)(
            transcript.bit_commitments, transcript.proof, transcript.zeta,
            (3, 1, 0, 0, 0, 0, 0, 0),
        )
        self.assertFalse(verify_independent_transcript(
            self.base, self.e, self.f, self.g, changed,
        ))

    def test_matrix_key_is_not_local_hmc_key(self):
        self.assertFalse(hasattr(RawHMCKey, "commit") and RawHMCKey.commit.__module__ == "pqct.hmc")


if __name__ == "__main__":
    unittest.main()
