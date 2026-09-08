import unittest

from pqct.binary_protocol1 import Protocol1Error, Protocol1Parameters, prove_protocol1
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.ring_commitment import ToyParameters


class Protocol1DimensionTests(unittest.TestCase):
    def test_protocol1_uses_one_ring_element_per_bit_in_e_and_f(self):
        p = ToyParameters(n=2, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, p)
        base = HMCKey(((r((1, 0)),),), ((r((1, 0)), r((0, 1))),), p)
        bits = ((r((0, 0)), r((1, 0))),)
        openings = ((r((1, 0)),),)
        commitments = (base.commit(bits[0], openings[0]),)
        e = HMCKey(((r((1, 0)),),), (tuple(r((1, 0)) for _ in range(2)),), p)
        f = e
        g = HMCKey(((r((1, 0)),),), ((r((1, 0)), r((0, 1))),), p)
        masks = (((r((1, 0)),), (r((1, 0)),)),)
        with self.assertRaises(Protocol1Error):
            prove_protocol1(
                b"dimension-test", base, e, f, g, commitments, bits, openings,
                masks, (r((1, 0)),), (r((1, 0)),), (r((1, 0)),),
                Protocol1Parameters(100, 100, 3),
            )


if __name__ == "__main__":
    unittest.main()
