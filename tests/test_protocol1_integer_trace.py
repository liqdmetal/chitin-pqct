import unittest

from pqct.binary_protocol1_ring import RingProtocol1Parameters, build_protocol1_ring_transcript
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.protocol1_integer_trace import trace_protocol1_pair, trace_protocol1_response
from pqct.ring_commitment import ToyParameters


class Protocol1IntegerTraceTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        one = r((1, 0, 0, 0, 0, 0, 0, 0))
        zero = r((0, 0, 0, 0, 0, 0, 0, 0))
        self.base = HMCKey(((one,),), ((one, r((0, 1, 0, 0, 0, 0, 0, 0))),), self.params)
        self.e = HMCKey(((one,),), (tuple(one for _ in range(4)),), self.params)
        self.f = self.e
        self.g = self.base
        self.bits = ((zero, one), (one, zero))
        self.openings = ((one,), (r((2, 0, 0, 0, 0, 0, 0, 0)),))
        self.masks = ((r((1, 1, 0, 0, 0, 0, 0, 0)), r((2, 0, 1, 0, 0, 0, 0, 0))),
                      (r((2, 0, 1, 0, 0, 0, 0, 0)), r((3, 1, 1, 0, 0, 0, 0, 0))))
        self.re = (one,)
        self.rf = (one,)
        self.rt = ((one,), (r((2, 0, 0, 0, 0, 0, 0, 0)),))
        self.zeta = one
        self.params_p1 = RingProtocol1Parameters(3, 1, 100000, 100000, 100000)
        self.commitments = tuple(self.base.commit(bits, opening) for bits, opening in zip(self.bits, self.openings))

    def _proof(self, x):
        return build_protocol1_ring_transcript(
            b"trace", self.base, self.e, self.f, self.g, self.commitments,
            self.bits, self.openings, self.masks, self.re, self.rf, self.rt,
            self.params_p1, zeta=self.zeta, challenge_x=x,
        )

    def _inputs(self):
        return self.bits, self.openings, self.masks, self.re, self.rf, self.rt

    def test_response_trace_records_intermediates(self):
        x = self.r((2, 1, 0, 0, 0, 0, 0, 0))
        report = trace_protocol1_response(self._proof(x), x, self.zeta, *self._inputs())
        self.assertTrue(report.safe)
        labels = {item.label for item in report.observations}
        self.assertIn("h[0][0]", labels)
        self.assertIn("x_h[1][1]", labels)
        self.assertIn("z_b_row[0][0]", labels)
        self.assertGreater(report.checked_values, 20)

    def test_pair_trace_records_extraction_operations(self):
        x0 = self.r((1, 0, 0, 0, 0, 0, 0, 0))
        x1 = self.r((2, 1, 0, 0, 0, 0, 0, 0))
        report = trace_protocol1_pair(
            self._proof(x0), self._proof(x1), x0, x1, self.zeta,
            first_inputs=self._inputs(),
        )
        self.assertTrue(report.safe)
        labels = {item.label for item in report.pair.observations}
        self.assertIn("pair.y", labels)
        self.assertIn("pair.t_hat[0]", labels)
        self.assertIn("pair.e_hat[0]", labels)
        self.assertIn("pair.s_hat[0]", labels)

    def test_pair_without_inputs_is_rejected_as_incomplete(self):
        from pqct.protocol1_integer_trace import IntegerTraceError
        x = self.r((1, 0, 0, 0, 0, 0, 0, 0))
        with self.assertRaises(IntegerTraceError):
            trace_protocol1_pair(self._proof(x), self._proof(x), x, x, self.zeta)

    def test_pair_shape_mismatch_is_rejected(self):
        from pqct.protocol1_integer_trace import IntegerTraceError
        x = self.r((1, 0, 0, 0, 0, 0, 0, 0))
        malformed = self._proof(x)
        malformed = type(malformed)(
            malformed.commitment_e, malformed.commitment_f, malformed.commitment_g,
            malformed.responses_g[:-1], malformed.response_zg, malformed.response_zb,
        )
        with self.assertRaises(IntegerTraceError):
            trace_protocol1_pair(self._proof(x), malformed, x, x, self.zeta, first_inputs=self._inputs())

    def test_small_modulus_reports_intermediate_wraparound(self):
        params = ToyParameters(n=8, q=17, k=1)
        r = lambda values: bounded_ring_element(values, params)
        one = r((1, 0, 0, 0, 0, 0, 0, 0))
        zero = r((0, 0, 0, 0, 0, 0, 0, 0))
        base = HMCKey(((one,),), ((one, r((0, 1, 0, 0, 0, 0, 0, 0))),), params)
        e = HMCKey(((one,),), (tuple(one for _ in range(2)),), params)
        bits = ((zero, one),)
        openings = ((one,),)
        masks = ((r((8, 0, 0, 0, 0, 0, 0, 0)), zero),)
        commitments = (base.commit(bits[0], openings[0]),)
        p = RingProtocol1Parameters(1, 1, 100000, 100000, 100000)
        proof = build_protocol1_ring_transcript(
            b"small", base, e, e, base, commitments, bits, openings, masks,
            (one,), (one,), ((one,),), p,
            zeta=one, challenge_x=r((2, 0, 0, 0, 0, 0, 0, 0)),
        )
        report = trace_protocol1_response(
            proof, r((2, 0, 0, 0, 0, 0, 0, 0)), one, bits, openings,
            masks, (one,), (one,), ((one,),),
        )
        self.assertFalse(report.safe)
        self.assertTrue(any("q/2" in violation for violation in report.violations))


if __name__ == "__main__":
    unittest.main()
