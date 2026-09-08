import unittest

from pqct.hmc import HMCKey, bounded_ring_element
from pqct.protocol1_rejection_audit import RejectionAuditError, build_rejection_tuple_audit
from pqct.ring_commitment import ToyParameters


class Protocol1RejectionAuditTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=4, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        self.zero = r((0, 0, 0, 0))
        self.one = r((1, 0, 0, 0))
        self.challenge = r((2, 1, 0, 0))
        self.bits = ((0, 1), (1, 0))
        self.t = ((r((1, 0, 0, 0)), r((0, 1, 0, 0))),
                  (r((2, 0, 0, 0)), r((0, 0, 1, 0))))
        self.r_e = (r((1, 0, 0, 0)),)
        self.r_f = (r((2, 0, 0, 0)),)
        self.openings = ((r((3, 0, 0, 0)),), (r((4, 0, 0, 0)),))
        self.r_t = ((r((1, 0, 0, 0)),), (r((2, 0, 0, 0)),))
        self.responses_g = self.t
        self.response_zg = (r((3, 1, 0, 0)),)
        self.response_zb_by_index = ((r((4, 0, 0, 0)),), (r((5, 0, 0, 0)),))

    def _audit(self):
        return build_rejection_tuple_audit(
            challenge=self.challenge, bits=self.bits, t=self.t,
            r_e=self.r_e, r_f=self.r_f, openings=self.openings,
            r_t=self.r_t, responses_g=self.responses_g,
            response_zg=self.response_zg,
            response_zb_by_index=self.response_zb_by_index,
        )

    def test_second_shift_uses_ring_products_and_per_index_zb(self):
        audit = self._audit()
        self.assertEqual(audit.first_dimension, 16)
        self.assertEqual(audit.second_dimension, 12)
        expected = tuple(value for element in (
            self.challenge.mul(self.r_e[0]),
            self.challenge.mul(self.openings[0][0]),
            self.challenge.mul(self.openings[1][0]),
        ) for value in element.coeffs)
        self.assertEqual(audit.second_shift, expected)

    def test_aggregate_zb_cannot_replace_per_index_tuple(self):
        audit = self._audit()
        self.assertEqual(audit.second_dimension, 12)
        self.assertNotEqual(audit.second_response, tuple(
            value for element in (self.response_zg[0], self.response_zb_by_index[0][0].add(self.response_zb_by_index[1][0]))
            for value in element.coeffs
        ))

    def test_malformed_width_rejected(self):
        with self.assertRaises(RejectionAuditError):
            build_rejection_tuple_audit(
                challenge=self.challenge, bits=self.bits, t=self.t,
                r_e=self.r_e, r_f=self.r_f, openings=self.openings,
                r_t=self.r_t, responses_g=self.responses_g,
                response_zg=self.response_zg,
                response_zb_by_index=((self.response_zb_by_index[0][0],),),
            )


if __name__ == "__main__":
    unittest.main()
