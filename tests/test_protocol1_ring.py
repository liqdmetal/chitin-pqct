import unittest

from pqct.binary_protocol1_ring import (
    RingProtocol1Parameters,
    prove_protocol1_ring,
    verify_protocol1_ring,
)
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.ring_commitment import ToyParameters


class RingProtocol1Tests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        self.base = HMCKey(
            G_r=((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
            G_m=((r((1, 0, 0, 0, 0, 0, 0, 0)), r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=self.params,
        )
        # Protocol 1 E/F commit one ring element per bit; G commits one per bit-column.
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
        self.masks = (
            (r((1, 0, 0, 0, 0, 0, 0, 0)), r((2, 0, 0, 0, 0, 0, 0, 0))),
            (r((3, 0, 0, 0, 0, 0, 0, 0)), r((4, 0, 0, 0, 0, 0, 0, 0))),
        )
        self.re = (r((1, 0, 0, 0, 0, 0, 0, 0)),)
        self.rf = (r((2, 0, 0, 0, 0, 0, 0, 0)),)
        self.rt = ((r((3, 0, 0, 0, 0, 0, 0, 0)),), (r((4, 0, 0, 0, 0, 0, 0, 0)),))
        self.proof_params = RingProtocol1Parameters(3, 5, 1000, 1000, 1000)

    def make_proof(self):
        return prove_protocol1_ring(
            b"ring-protocol1", self.base, self.e, self.f, self.g,
            self.commitments, self.bits, self.openings, self.masks,
            self.re, self.rf, self.rt, self.proof_params,
        )

    def test_honest_ring_equations_verify(self):
        proof = self.make_proof()
        self.assertTrue(verify_protocol1_ring(
            b"ring-protocol1", self.base, self.e, self.f, self.g,
            self.commitments, proof, self.proof_params,
        ))

    def test_statement_mutation_fails(self):
        self.assertFalse(verify_protocol1_ring(
            b"other", self.base, self.e, self.f, self.g,
            self.commitments, self.make_proof(), self.proof_params,
        ))

    def test_proof_commitment_mutation_fails(self):
        proof = self.make_proof()
        mutated = type(proof)(
            self.base.commit((self.r((1, 0, 0, 0, 0, 0, 0, 0)), self.r((0, 0, 0, 0, 0, 0, 0, 0))), self.re),
            proof.commitment_f, proof.commitment_g,
            proof.responses_g, proof.response_zg, proof.response_zb,
        )
        self.assertFalse(verify_protocol1_ring(
            b"ring-protocol1", self.base, self.e, self.f, self.g,
            self.commitments, mutated, self.proof_params,
        ))


if __name__ == "__main__":
    unittest.main()
