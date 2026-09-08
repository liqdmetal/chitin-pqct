import unittest


class BalanceRelationTests(unittest.TestCase):
    @staticmethod
    def bits(value: int, width: int) -> list[int]:
        if value < 0 or value >= (1 << width):
            raise ValueError("value outside unsigned bit width")
        return [(value >> j) & 1 for j in range(width)]

    @staticmethod
    def weighted_bit_relation(values: list[int], weights: list[int], width: int) -> int:
        return sum(weight * value for value, weight in zip(values, weights))

    @staticmethod
    def bitwise_relation(values: list[int], weights: list[int], width: int) -> list[int]:
        columns = [BalanceRelationTests.bits(value, width) for value in values]
        return [sum(weight * column[j] for weight, column in zip(weights, columns)) for j in range(width)]

    def test_bitwise_relation_matches_integer_relation(self):
        values = [13, 8, 5]
        weights = [-1, 1, 1]
        width = 4
        columns = self.bitwise_relation(values, weights, width)
        self.assertEqual(sum((1 << j) * c for j, c in enumerate(columns)), 0)
        self.assertEqual(self.weighted_bit_relation(values, weights, width), 0)

    def test_nonconserving_values_are_not_hidden_by_bit_columns(self):
        values = [13, 8, 4]
        weights = [-1, 1, 1]
        width = 4
        columns = self.bitwise_relation(values, weights, width)
        self.assertNotEqual(sum((1 << j) * c for j, c in enumerate(columns)), 0)
        self.assertNotEqual(self.weighted_bit_relation(values, weights, width), 0)

    def test_account_statement_includes_fee(self):
        old_balance = 100
        credits = 0
        new_balance = 70
        debits = 25
        fee = 5
        self.assertEqual(old_balance + credits - new_balance - debits - fee, 0)

    def test_unsigned_range_boundary(self):
        self.assertEqual(self.bits(255, 8), [1] * 8)
        with self.assertRaises(ValueError):
            self.bits(256, 8)
        with self.assertRaises(ValueError):
            self.bits(-1, 8)


if __name__ == "__main__":
    unittest.main()
