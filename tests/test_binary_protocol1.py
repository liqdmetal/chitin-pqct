import unittest

from pqct.binary_protocol1 import Protocol1Error, _check_binary_commitments
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.ring_commitment import RingElement, ToyParameters


class Protocol1BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=4, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        self.key = HMCKey(
            G_r=((r((1, 0, 0, 0)),),),
            G_m=((r((1, 0, 0, 0)),),),
            params=self.params,
        )
        self.opening = (r((2, 0, 0, 0)),)

    def test_constant_binary_polynomial_is_accepted(self):
        message = (self.r((1, 0, 0, 0)),)
        public = (self.key.commit(message, self.opening),)
        _check_binary_commitments(self.key, public, (message,), (self.opening,))

    def test_nonconstant_binary_polynomial_is_rejected(self):
        message = (self.r((1, 1, 0, 0)),)
        public = (self.key.commit(message, self.opening),)
        with self.assertRaises(Protocol1Error):
            _check_binary_commitments(self.key, public, (message,), (self.opening,))


if __name__ == "__main__":
    unittest.main()
