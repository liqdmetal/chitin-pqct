import unittest

from pqct.parameters import GaoPaperProfile, ParameterError, ToyProfile, cycle_mask_bound, response_bound


class ParameterTests(unittest.TestCase):
    def test_paper_profile_is_explicit_and_valid(self):
        profile = GaoPaperProfile()
        profile.validate()
        self.assertEqual(profile.amount_bits, 64)
        self.assertEqual(profile.outputs, 1)
        self.assertGreater(profile.challenge_count_lower_bound, 0)
        self.assertGreaterEqual(profile.modulus_bits, 49)

    def test_toy_profile_cannot_claim_security(self):
        ToyProfile().validate()
        with self.assertRaises(ParameterError):
            ToyProfile(security_bits=128).validate()

    def test_bounds_are_conservative(self):
        self.assertEqual(response_bound(31, 2, 4), 66)
        self.assertEqual(cycle_mask_bound(4, 64), 12)
        with self.assertRaises(ParameterError):
            response_bound(-1, 2, 3)


if __name__ == "__main__":
    unittest.main()
