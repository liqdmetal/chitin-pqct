import unittest

from pqct.protocol1_extraction import (
    ExtractionError,
    extract_second_layer,
    validate_third_x_transcript,
)
from pqct.binary_protocol1_ring import RingProtocol1Proof
from pqct.ring_commitment import RingElement, ToyParameters


class ThirdTranscriptConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        self.r = lambda values: RingElement.from_coeffs(values, self.params)
        self.one = self.r((1, 0, 0, 0, 0, 0, 0, 0))
        self.zeta = self.one
        self.xs = (
            self.one,
            self.r((2, 0, 0, 0, 0, 0, 0, 0)),
            self.r((3, 0, 0, 0, 0, 0, 0, 0)),
        )

    def _proof(self, delta):
        a = self.r((1 + delta, 0, 0, 0, 0, 0, 0, 0))
        b = self.r((2 + delta, 0, 0, 0, 0, 0, 0, 0))
        c = self.r((3 + delta, 0, 0, 0, 0, 0, 0, 0))
        return RingProtocol1Proof(
            (self.one,), (self.one,), (self.one,),
            ((a, b),), (c,), (a,),
        )

    def test_third_transcript_is_checked(self):
        proofs = (self._proof(0), self._proof(1), self._proof(2))
        extraction = extract_second_layer(self.xs, proofs, self.zeta)
        tampered = RingProtocol1Proof(
            proofs[2].commitment_e,
            proofs[2].commitment_f,
            proofs[2].commitment_g,
            proofs[2].responses_g,
            (proofs[2].response_zg[0].add(self.one),),
            proofs[2].response_zb,
        )
        self.assertFalse(validate_third_x_transcript(
            extraction, self.xs[2], tampered, self.zeta,
        ))


if __name__ == "__main__":
    unittest.main()
