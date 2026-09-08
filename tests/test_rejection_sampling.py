import unittest

from pqct.rejection_sampling import (
    RejectionSamplingError,
    acceptance_probability,
    accept_candidate,
    accepts,
    log_acceptance_ratio,
)


class RejectionSamplingTests(unittest.TestCase):
    def test_probability_matches_gaussian_ratio(self):
        probability = acceptance_probability((3, 1), (1, 1), 2.0, 4.0)
        self.assertAlmostEqual(probability, 0.1180916382, places=9)

    def test_accept_and_reject_decisions_are_explicit(self):
        args = ((3, 1), (1, 1), 2.0, 4.0)
        self.assertTrue(accepts(*args, 0.1))
        self.assertFalse(accepts(*args, 0.99))

    def test_candidate_response_is_mask_plus_shift(self):
        sample = accept_candidate((2, -1), (1, 1), 2.0, 4.0, 0.0)
        self.assertIsNotNone(sample)
        self.assertEqual(sample.response, (3, 0))

    def test_bad_majorant_and_uniform_values_rejected(self):
        with self.assertRaises(RejectionSamplingError):
            acceptance_probability((10,), (1,), 1.0, 0.5)
        with self.assertRaises(RejectionSamplingError):
            accepts((1,), (1,), 1.0, 2.0, 1.0)
        self.assertLess(log_acceptance_ratio((1,), (0,), 1.0, 2.0), 0)


if __name__ == "__main__":
    unittest.main()
