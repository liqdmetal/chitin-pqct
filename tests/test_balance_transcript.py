import unittest

from pqct.balance_composition import SignedAmount
from pqct.balance_transcript import BalanceTranscriptError
from pqct.balance_transcript import build_balance_transcript
from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.protocol1_sampling import Protocol1DistributionParameters
from pqct.ring_commitment import ToyParameters


class BalanceTranscriptTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        unit = r((1, 0, 0, 0, 0, 0, 0, 0))
        self.base = HMCKey(
            G_r=((unit,),),
            G_m=((unit, r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=self.params,
        )
        self.distribution = Protocol1DistributionParameters(
            B=1, gaussian_tail=8, phi1=1, phi2=2,
        )
        self.proof_params = RingProtocol1Parameters.from_paper_bounds(
            challenge_weight=2, challenge_coefficient_bound=1,
            B=1, p=1, k=2, m=1, d=8,
            phi1=2, phi2=8,
        )

    def _build(self, amounts, seed=b"balance-seed"):
        return build_balance_transcript(
            seed=seed, statement=b"balance-statement",
            base_key=self.base, key_e=self.base, key_f=self.base, key_g=self.base,
            amounts=amounts, bit_width=2, p=1, w=2,
            distribution=self.distribution, params=self.proof_params,
            max_attempts=512,
        )

    def test_conserved_transaction_composes_and_checks(self):
        amounts = (
            SignedAmount(1, 1), SignedAmount(1, 1), SignedAmount(2, -1),
        )
        transcript = self._build(amounts)
        self.assertEqual(len(transcript.amounts), 3)
        self.assertTrue(transcript.combination_opening_ok)
        self.assertTrue(transcript.conservation_exact)
        self.assertTrue(transcript.all_ok)
        for entry in transcript.amounts:
            self.assertTrue(entry.proof.rejection.accepted)
            self.assertGreaterEqual(entry.proof.attempts, 1)

    def test_non_conserved_transaction_flags_conservation_only(self):
        amounts = (
            SignedAmount(1, 1), SignedAmount(1, 1), SignedAmount(1, -1),
        )
        transcript = self._build(amounts, seed=b"nonconserved-seed")
        self.assertTrue(transcript.combination_opening_ok)
        self.assertFalse(transcript.conservation_exact)
        self.assertFalse(transcript.all_ok)

    def test_out_of_range_amount_rejected(self):
        with self.assertRaises(BalanceTranscriptError):
            self._build((SignedAmount(4, 1),))

    def test_empty_seed_rejected(self):
        with self.assertRaises(BalanceTranscriptError):
            self._build((SignedAmount(1, 1),), seed=b"")

    def test_bit_width_must_match_key(self):
        with self.assertRaises(BalanceTranscriptError):
            build_balance_transcript(
                seed=b"s", statement=b"st",
                base_key=self.base, key_e=self.base, key_f=self.base,
                key_g=self.base,
                amounts=(SignedAmount(1, 1),), bit_width=3, p=1, w=2,
                distribution=self.distribution, params=self.proof_params,
            )

    def test_transcript_is_reproducible(self):
        amounts = (SignedAmount(1, 1), SignedAmount(1, -1))
        first = self._build(amounts, seed=b"repro-seed")
        second = self._build(amounts, seed=b"repro-seed")
        self.assertEqual(first.combined_commitment, second.combined_commitment)
        self.assertEqual(first.columns.columns, second.columns.columns)
        self.assertEqual(first.all_ok, second.all_ok)

    def test_tampered_column_vector_breaks_combination_check(self):
        """Mutating c_j's claimed value must fail the eq.(11) opening check."""
        amounts = (SignedAmount(1, 1), SignedAmount(1, 1), SignedAmount(2, -1))
        transcript = self._build(amounts, seed=b"tamper-seed")
        self.assertTrue(transcript.combination_opening_ok)
        tampered = tuple(
            value + 1 if index == 0 else value
            for index, value in enumerate(transcript.columns.columns)
        )
        from pqct.hmc import bounded_ring_element
        tampered_elements = tuple(
            bounded_ring_element((value,) + (0,) * (self.params.n - 1), self.params)
            for value in tampered
        )
        recomputed = self.base.commit(
            tampered_elements, transcript.combined_randomness,
        )
        self.assertNotEqual(recomputed, transcript.combined_commitment)


if __name__ == "__main__":
    unittest.main()
