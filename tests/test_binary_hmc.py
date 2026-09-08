import unittest

from pqct.binary_hmc import (
    BinaryProofParameters,
    BinaryTranscriptError,
    prove_binary,
    verify_binary,
)
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.ring_commitment import ToyParameters


class BinaryHMCTranscriptTests(unittest.TestCase):
    def setUp(self):
        self.p = ToyParameters(n=2, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.p)
        self.base = HMCKey(
            G_r=((r((1, 0)),),),
            G_m=((r((1, 0)), r((0, 1))),),
            params=self.p,
        )
        # E/F commit two flattened width-2 vectors; G commits one width-2 vector.
        self.e = HMCKey(
            G_r=((r((1, 0)),),),
            G_m=((r((1, 0)), r((0, 1)), r((1, 1)), r((1, 2))),),
            params=self.p,
        )
        self.f = self.e
        self.g = self.base
        self.bits = ((0, 1), (1, 0))
        self.opens = ((r((2, 0)),), (r((3, 0)),))
        self.commitments = tuple(self.base.commit(tuple(r((bit, 0)) for bit in vector), opening) for vector, opening in zip(self.bits, self.opens))
        self.masks = (
            ((r((2, 0)),), (r((1, 0)),)),
            ((r((3, 0)),), (r((2, 0)),)),
        )
        self.re = (r((1, 0)),)
        self.rf = (r((2, 0)),)
        self.rg = (r((3, 0)),)
        self.params = BinaryProofParameters(response_bound=1000, opening_bound=1000)

    def make_proof(self):
        return prove_binary(
            b"binary-test", self.base, self.e, self.f, self.g,
            self.commitments, self.bits, self.opens, self.masks,
            self.re, self.rf, self.rg, self.params,
        )

    def test_honest_transcript_verifies(self):
        proof = self.make_proof()
        self.assertTrue(verify_binary(
            b"binary-test", self.base, self.e, self.f, self.g,
            self.commitments, proof, self.params,
        ))

    def test_public_commitment_must_match_every_witness(self):
        bad_commitments = list(self.commitments)
        bad_commitments[0] = self.base.commit(tuple(bounded_ring_element((1, 0), self.p) for _ in self.bits[0]), self.opens[0])
        with self.assertRaises(BinaryTranscriptError):
            prove_binary(
                b"binary-test", self.base, self.e, self.f, self.g,
                tuple(bad_commitments), self.bits, self.opens, self.masks,
                self.re, self.rf, self.rg, self.params,
            )

    def test_statement_binding(self):
        self.assertFalse(verify_binary(
            b"other", self.base, self.e, self.f, self.g,
            self.commitments, self.make_proof(), self.params,
        ))

    def test_nonbinary_witness_is_rejected(self):
        with self.assertRaises(BinaryTranscriptError):
            prove_binary(
                b"binary-test", self.base, self.e, self.f, self.g,
                self.commitments, ((0, 2), (1, 0)), self.opens, self.masks,
                self.re, self.rf, self.rg, self.params,
            )


if __name__ == "__main__":
    unittest.main()
