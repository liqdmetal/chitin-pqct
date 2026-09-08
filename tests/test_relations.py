import unittest

from pqct.relations import (
    account_conservation,
    bit_columns,
    packed_bit_relation,
    weighted_relation,
)


class RelationTests(unittest.TestCase):
    def test_packed_columns_equal_exact_relation(self):
        values = (100, 7, 90, 12, 5)
        weights = (1, 1, -1, -1, -1)
        columns = bit_columns(values, weights, 8)
        self.assertEqual(packed_bit_relation(values, weights, 8), 0)
        self.assertEqual(weighted_relation(values, weights, 8), 0)
        self.assertTrue(any(column != 0 for column in columns))

    def test_account_conservation_accepts_fee(self):
        self.assertTrue(account_conservation(100, 7, 90, 12, 5, 8))

    def test_account_conservation_rejects_missing_fee(self):
        self.assertFalse(account_conservation(100, 7, 90, 12, 4, 8))

    def test_width_and_shape_are_strict(self):
        with self.assertRaises(ValueError):
            weighted_relation((1, 2), (1,), 8)
        with self.assertRaises(ValueError):
            weighted_relation((256,), (1,), 8)
        with self.assertRaises(ValueError):
            bit_columns((1,), (1,), 0)


if __name__ == "__main__":
    unittest.main()
