import unittest
from decimal import Decimal

from pqct.parameter_validation import ParameterValidationError
from pqct.parameter_validation import validate_protocol1_parameters
from pqct.parameter_validation import validate_protocol5_parameters

PAPER_Q = 2**49 - 2**18 + 2**9 + 1


class Protocol1ValidationTests(unittest.TestCase):
    def test_paper_profile_passes_precondition_and_yields_hardness(self):
        v = validate_protocol1_parameters(
            q=PAPER_Q, n=29, d=64, w=56, p=8, k=64,
            phi1=Decimal(11), phi2=Decimal(11), B=1, m=60,
        )
        self.assertTrue(v.q_precondition_holds)
        self.assertGreater(v.gamma_bin_required, 0)
        self.assertIsNotNone(v.hardness)
        self.assertGreater(v.hardness.classical_bits, 0)
        self.assertGreater(v.hardness.classical_bits, v.hardness.quantum_bits)
        self.assertIn("precondition OK", v.note)

    def test_toy_fixture_fails_precondition(self):
        """The lab's toy params do NOT meet Theorem 1's q/2 condition.

        Pinned so a future change cannot silently pretend the toy fixture
        carries the paper's soundness guarantee.
        """
        v = validate_protocol1_parameters(
            q=12289, n=32, d=32, w=4, p=2, k=5,
            phi1=Decimal(1), phi2=Decimal(2), B=1, m=1,
        )
        self.assertFalse(v.q_precondition_holds)
        self.assertIn("FAILS", v.note)

    def test_rejects_bad_dimensions(self):
        with self.assertRaises(ParameterValidationError):
            validate_protocol1_parameters(
                q=PAPER_Q, n=0, d=64, w=56, p=8, k=64,
                phi1=Decimal(11), phi2=Decimal(11), B=1, m=60,
            )

    def test_larger_phi1_tightens_precondition(self):
        small = validate_protocol1_parameters(
            q=PAPER_Q, n=29, d=64, w=56, p=8, k=64,
            phi1=Decimal(11), phi2=Decimal(11), B=1, m=60,
        )
        huge = validate_protocol1_parameters(
            q=PAPER_Q, n=29, d=64, w=56, p=8, k=64,
            phi1=Decimal(10**9), phi2=Decimal(11), B=1, m=60,
        )
        self.assertTrue(small.q_precondition_holds)
        self.assertFalse(huge.q_precondition_holds)


class Protocol5ValidationTests(unittest.TestCase):
    def test_paper_profile_yields_hardness(self):
        v = validate_protocol5_parameters(
            q=PAPER_Q, n=29, d=64, w=56, p=8,
            phi3=Decimal(11), B=1, m=60, omega_l1=3, account_count=3,
        )
        self.assertGreater(v.gamma_le_required, 0)
        self.assertIsNotNone(v.hardness)
        self.assertGreater(v.hardness.classical_bits, 0)

    def test_gamma_le_grows_with_account_count(self):
        small = validate_protocol5_parameters(
            q=PAPER_Q, n=29, d=64, w=56, p=8,
            phi3=Decimal(11), B=1, m=60, omega_l1=3, account_count=3,
        )
        large = validate_protocol5_parameters(
            q=PAPER_Q, n=29, d=64, w=56, p=8,
            phi3=Decimal(11), B=1, m=60, omega_l1=3, account_count=50,
        )
        self.assertGreater(large.gamma_le_required, small.gamma_le_required)

    def test_rejects_zero_account_count(self):
        with self.assertRaises(ParameterValidationError):
            validate_protocol5_parameters(
                q=PAPER_Q, n=29, d=64, w=56, p=8,
                phi3=Decimal(11), B=1, m=60, omega_l1=3, account_count=0,
            )


if __name__ == "__main__":
    unittest.main()
