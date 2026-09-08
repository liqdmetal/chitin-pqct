import unittest

from pqct.reduced_transcript import (
    ReducedProof,
    ReducedRelationParameters,
    SequenceIntSampler,
    ToyVectorCommitmentKey,
    prove_reduced_relation,
    verify_reduced_relation,
)


class ReducedTranscriptTests(unittest.TestCase):
    def setUp(self):
        self.key = ToyVectorCommitmentKey((3, 5, 7), 11, 12289)
        self.statement = b"account-v0|asset-demo|epoch-1"
        self.columns = (2, -1, 0)  # 2 - 2 + 0 = 0
        self.opening = 7
        self.params = ReducedRelationParameters(
            mask_sample_bound=4,
            response_bound=50000,
            opening_bound=100000,
        )

    def make_proof(self):
        return prove_reduced_relation(
            self.key,
            self.statement,
            self.columns,
            self.opening,
            SequenceIntSampler((2, -1, 3)),
            self.params,
        )

    def test_honest_transcript_verifies(self):
        relation_commitment = self.key.commit(self.columns, self.opening)
        self.assertTrue(
            verify_reduced_relation(
                self.key,
                self.statement,
                relation_commitment,
                self.make_proof(),
                self.params,
            )
        )

    def test_tampered_response_is_rejected(self):
        proof = self.make_proof()
        relation_commitment = self.key.commit(self.columns, self.opening)
        tampered = ReducedProof(
            proof.mask_commitment,
            (proof.response_tail[0] + 1, *proof.response_tail[1:]),
            proof.opening_response,
        )
        self.assertFalse(
            verify_reduced_relation(self.key, self.statement, relation_commitment, tampered, self.params)
        )

    def test_statement_binding_is_rejected(self):
        relation_commitment = self.key.commit(self.columns, self.opening)
        self.assertFalse(
            verify_reduced_relation(
                self.key,
                b"account-v0|asset-demo|epoch-2",
                relation_commitment,
                self.make_proof(),
                self.params,
            )
        )

    def test_nonconserving_relation_cannot_be_proved(self):
        with self.assertRaises(ValueError):
            prove_reduced_relation(
                self.key,
                self.statement,
                (2, -1, 1),
                self.opening,
                SequenceIntSampler((2, -1, 3)),
                self.params,
            )

    def test_modular_zero_does_not_bypass_exact_relation(self):
        proof = self.make_proof()
        relation_commitment = self.key.commit(self.columns, self.opening)
        bad_params = ReducedRelationParameters(4, 12289, 50000)
        self.assertFalse(
            verify_reduced_relation(
                self.key,
                self.statement,
                relation_commitment,
                ReducedProof(proof.mask_commitment, (proof.response_tail[0] + 12289, *proof.response_tail[1:]), proof.opening_response),
                bad_params,
            )
        )


if __name__ == "__main__":
    unittest.main()
