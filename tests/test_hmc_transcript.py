import unittest

from pqct.hmc import HMCKey, bounded_ring_element
from pqct.hmc_transcript import (
    HMCProof,
    HMCTranscriptError,
    prove_hmc_relation,
    verify_hmc_relation,
)
from pqct.ring_commitment import ToyParameters


class HMCTranscriptTests(unittest.TestCase):
    def setUp(self):
        self.p = ToyParameters(n=4, q=12289, k=2)
        r = lambda values: bounded_ring_element(values, self.p)
        self.key = HMCKey(
            G_r=((r((1, 0, 1, 0)), r((0, 1, 0, 1))), (r((2, 1, 0, 0)), r((0, 0, 1, 2)))),
            G_m=((r((1, 1, 0, 0)), r((0, 1, 1, 0)), r((1, 0, 0, 1))), (r((1, 0, 0, 1)), r((2, 0, 1, 0)), r((0, 1, 1, 0)))),
            params=self.p,
        )
        self.r = r
        self.columns = (r((6, 0, 0, 0)), r((1, 0, 0, 0)), r((-2, 0, 0, 0)))
        self.relation_opening = (r((2, 0, 1, 0)), r((0, 1, 0, 2)))
        self.mask = (r((18, 0, 0, 0)), r((3, 0, 0, 0)), r((-6, 0, 0, 0)))
        self.mask_opening = (r((1, 0, 0, 0)), r((0, 2, 0, 0)))
        self.statement = b"account=toy;asset=dero;nonce=7"

    def make_proof(self):
        relation_commitment = self.key.commit(self.columns, self.relation_opening)
        proof = prove_hmc_relation(self.key, self.statement, self.columns, self.relation_opening, self.mask, self.mask_opening)
        return relation_commitment, proof

    def test_honest_hmc_transcript_verifies(self):
        commitment, proof = self.make_proof()
        self.assertTrue(verify_hmc_relation(self.key, self.statement, commitment, proof))

    def test_tampered_hmc_response_fails(self):
        commitment, proof = self.make_proof()
        changed = self.r((proof.response_tail[0].coeffs[0] + 1, 0, 0, 0))
        tampered = HMCProof(proof.mask_commitment, (changed, *proof.response_tail[1:]), proof.opening_response)
        self.assertFalse(verify_hmc_relation(self.key, self.statement, commitment, tampered))

    def test_statement_binding_fails(self):
        commitment, proof = self.make_proof()
        self.assertFalse(verify_hmc_relation(self.key, b"nonce=8", commitment, proof))

    def test_nonconserving_relation_cannot_be_proved(self):
        bad = (self.r((6, 0, 0, 0)), self.r((1, 0, 0, 0)), self.r((-1, 0, 0, 0)))
        with self.assertRaises(HMCTranscriptError):
            prove_hmc_relation(self.key, self.statement, bad, self.relation_opening, self.mask, self.mask_opening)

    def test_modular_wraparound_is_rejected_by_integer_boundary(self):
        tail = (self.r((1, 0, 0, 0)), self.r((0, 0, 0, 0)))
        proof = HMCProof(tuple(self.key.commit(self.mask, self.mask_opening)), tail, self.mask_opening)
        commitment = self.key.commit(self.columns, self.relation_opening)
        self.assertFalse(verify_hmc_relation(self.key, self.statement, commitment, proof))


if __name__ == "__main__":
    unittest.main()
