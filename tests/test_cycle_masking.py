import unittest

from pqct.cycle_masking import (
    derive_cycle_mask,
    mask_relation,
    reconstruct_first_response,
    relation_response_is_exactly_zero,
)


class CycleMaskingTests(unittest.TestCase):
    def test_derived_mask_has_zero_weighted_sum(self):
        mask = derive_cycle_mask((0, 3, -2, 5, 0))
        self.assertEqual(mask.values, (-6, 7, -12, 5))
        self.assertEqual(mask.weighted_sum(), 0)

    def test_masked_relation_preserves_exact_relation(self):
        columns = (2, -1, 0)
        mask = derive_cycle_mask((0, 2, -1, 0))
        response = mask_relation(columns, 9, mask)
        self.assertTrue(relation_response_is_exactly_zero(response))

    def test_verifier_reconstructs_omitted_coordinate_over_integers(self):
        tail = (4, -3, 1)
        first = reconstruct_first_response(tail)
        response = (first, *tail)
        self.assertTrue(relation_response_is_exactly_zero(response))

    def test_modular_zero_is_not_integer_zero(self):
        # q=17 would make this weighted sum vanish modulo q, but not over Z.
        response = (17, 0, 0)
        self.assertFalse(relation_response_is_exactly_zero(response))

    def test_endpoint_and_dimension_rejection(self):
        with self.assertRaises(ValueError):
            derive_cycle_mask((1, 2, 0))
        with self.assertRaises(ValueError):
            derive_cycle_mask((0, 1))
        with self.assertRaises(ValueError):
            mask_relation((1,), 2, derive_cycle_mask((0, 1, 0)))


if __name__ == "__main__":
    unittest.main()
