import unittest

from pqct.binary_protocol1_ring import RingProtocol1Proof
from pqct.hmc import HMCKey
from pqct.protocol1_extraction import (
    ExtractionError,
    extract_second_layer,
    extract_second_layer_pair,
    validate_pairwise_consistency,
    validate_pairwise_negation,
)
from pqct.ring_commitment import RingElement, ToyParameters


class Protocol1ExtractionTests(unittest.TestCase):
    def _fixture(self):
        params = ToyParameters(n=8, q=12289, k=1)
        r = lambda values: RingElement.from_coeffs(values, params)
        key_g = HMCKey(
            G_r=((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
            G_m=((r((1, 0, 0, 0, 0, 0, 0, 0)), r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=params,
        )
        one = r((1, 0, 0, 0, 0, 0, 0, 0))
        base_proof = RingProtocol1Proof(
            (one,), (one,), (one,),
            ((one, one), (one, one)),
            (one,), (one,),
        )
        variants = []
        for delta in (one, one.add(one), one.add(one).add(one)):
            variants.append(RingProtocol1Proof(
                base_proof.commitment_e,
                base_proof.commitment_f,
                base_proof.commitment_g,
                tuple(tuple(value.add(delta) for value in row) for row in base_proof.responses_g),
                tuple(value.add(delta) for value in base_proof.response_zg),
                tuple(value.add(delta) for value in base_proof.response_zb),
            ))
        return params, key_g, variants, (one, one.add(one), one.add(one).add(one))

    def test_three_transcripts_extract_without_inversion(self):
        params, key_g, proofs, challenges = self._fixture()
        result = extract_second_layer(challenges, proofs, challenges[0])
        self.assertEqual(result.first_delta, challenges[0].sub(challenges[1]))
        self.assertEqual(result.second_delta, challenges[0].sub(challenges[2]))
        self.assertEqual(len(result.opening_sum_b.message), 2)
        self.assertEqual(len(result.opening_sum_b.randomness), 1)

    def test_pairwise_outputs_cross_check_all_three_pairs(self):
        params, key_g, proofs, challenges = self._fixture()
        zeta = challenges[0]
        pairs = []
        for i, j in ((0, 1), (0, 2), (1, 2)):
            pairs.append(extract_second_layer_pair(
                (challenges[i], challenges[j]), (proofs[i], proofs[j]), zeta,
                transcript_zetas=(zeta, zeta),
            ))
        self.assertTrue(validate_pairwise_consistency(
            pairs[0], proofs[0], proofs[1], challenges[0], challenges[1], challenges[0],
        ))
        self.assertTrue(validate_pairwise_consistency(
            pairs[1], proofs[0], proofs[2], challenges[0], challenges[2], challenges[0],
        ))
        self.assertTrue(validate_pairwise_consistency(
            pairs[2], proofs[1], proofs[2], challenges[1], challenges[2], challenges[0],
        ))
        self.assertTrue(validate_pairwise_negation(
            pairs[0],
            extract_second_layer_pair(
                (challenges[1], challenges[0]),
                (proofs[1], proofs[0]),
                zeta,
                transcript_zetas=(zeta, zeta),
            ),
        ))

    def test_duplicate_challenge_rejected(self):
        params, key_g, proofs, challenges = self._fixture()
        with self.assertRaises(ExtractionError):
            extract_second_layer((challenges[0], challenges[0], challenges[2]), proofs, challenges[0])

    def test_mismatched_commitments_rejected(self):
        params, key_g, proofs, challenges = self._fixture()
        changed = RingProtocol1Proof(
            proofs[1].commitment_e,
            proofs[1].commitment_f,
            (proofs[1].commitment_g[0].add(challenges[0]),),
            proofs[1].responses_g,
            proofs[1].response_zg,
            proofs[1].response_zb,
        )
        with self.assertRaises(ExtractionError):
            extract_second_layer(challenges, (proofs[0], changed, proofs[2]), challenges[0])

    def test_zeta_metadata_is_checked_when_supplied(self):
        params, key_g, proofs, challenges = self._fixture()
        one = challenges[0]
        two = challenges[1]
        with self.assertRaises(ExtractionError):
            extract_second_layer(
                challenges, proofs, one,
                transcript_zetas=(one, two, one),
            )
        result = extract_second_layer(
            challenges, proofs, one,
            transcript_zetas=(one, one, one),
        )
        self.assertEqual(result.first_delta, challenges[0].sub(challenges[1]))


if __name__ == "__main__":
    unittest.main()
