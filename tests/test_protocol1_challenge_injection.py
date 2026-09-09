"""Adversarial test: Protocol 1's verifier must not accept attacker-chosen challenges.

Public equations (verifier steps, zeta-power aggregation over commitment ROWS):

    weighted_public[j] = sum_i zeta^i * public[i][j]
    x * weighted_public + commitment_g = Com(weighted_g; z_b)
    x * commitment_e    + commitment_f = Com(e; z_g),  e = g_ij*(x - g_ij)

If a caller supplies (zeta, x), they pick SMALL responses first and solve both
commitments backwards, so a forged proof verifies against ANY commitments --
including ones encoding no bits. With FS derived challenges (the default) it
cannot.

Key shapes the verifier enforces (this test's original bug was here):
    public[i] has base.ring_rows entries; responses_g[i][j] has key_g.message_width
    entries == width; key_e/f message_width == count*width.
With base.ring_rows=1, width=1, count=2 the flat e_message has exactly 2*1=2
elements and key_g.message_width must be 1.
"""

import unittest

from pqct.binary_protocol1_ring import (
    RingProtocol1Parameters,
    RingProtocol1Proof,
    verify_protocol1_ring,
)
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.ring_commitment import RingElement, ToyParameters


class Protocol1ChallengeInjectionTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        self.one = r((1, 0, 0, 0, 0, 0, 0, 0))
        self.zero = RingElement.zero(self.params)

        # ring_rows=1, message_width=1 (one bit-column), randomness_width=1.
        self.base = HMCKey(G_r=((self.one,),), G_m=((self.one,),), params=self.params)
        # message_width = count*width = 2*1 = 2.
        self.e = HMCKey(
            G_r=((self.one,),), G_m=((self.one, self.one),), params=self.params
        )
        self.f = self.e
        # message_width = width = 1.
        self.g = HMCKey(G_r=((self.one,),), G_m=((self.one,),), params=self.params)

        self.count, self.width = 2, 1
        self.proof_params = RingProtocol1Parameters(3, 5, 1000, 1000, 1000)

    def _aggregate(self, rows, zeta_powers):
        """sum_i zeta^i * rows[i], elementwise -- mirrors the verifier."""
        total = tuple(self.zero for _ in range(len(rows[0])))
        for power, row in zip(zeta_powers, rows):
            total = tuple(t.add(v.mul(power)) for t, v in zip(total, row))
        return total

    def _forge(self, zeta, x, public):
        powers = [self.one]
        for _ in range(self.count - 1):
            powers.append(powers[-1].mul(zeta))

        weighted_public = self._aggregate(public, powers)

        responses_g = tuple(
            tuple(self.zero for _ in range(self.width)) for _ in range(self.count)
        )
        response_zg = tuple(self.zero for _ in range(self.e.randomness_width))
        response_zb = tuple(self.zero for _ in range(self.g.randomness_width))

        weighted_g = self._aggregate(responses_g, powers)

        commitment_g = tuple(
            v.sub(x.mul(p))
            for v, p in zip(self.g.commit(weighted_g, response_zb), weighted_public)
        )

        commitment_e = tuple(self.zero for _ in range(self.e.ring_rows))
        e_message = tuple(
            g.mul(x.sub(g)) for row in responses_g for g in row
        )
        commitment_f = tuple(
            v.sub(x.mul(e_row))
            for v, e_row in zip(self.e.commit(e_message, response_zg), commitment_e)
        )

        return RingProtocol1Proof(
            commitment_e=commitment_e,
            commitment_f=commitment_f,
            commitment_g=commitment_g,
            responses_g=responses_g,
            response_zg=response_zg,
            response_zb=response_zb,
        )

    def test_forgery_succeeds_only_when_challenges_are_attacker_chosen(self):
        # Commitments encoding NO bits (7 and 9 are not 0/1).
        bogus = ((self.r((7, 0, 0, 0, 0, 0, 0, 0)),), (self.r((3, 0, 0, 0, 0, 0, 0, 0)),))
        zeta = self.r((1, 1, 0, 0, 0, 0, 0, 0))
        x = self.r((2, 1, 0, 0, 0, 0, 0, 0))
        forged = self._forge(zeta, x, bogus)

        # (a) Vector is REAL: FS off, the forgery verifies against non-bits.
        self.assertTrue(verify_protocol1_ring(
            b"forge", self.base, self.e, self.f, self.g, bogus, forged,
            self.proof_params, zeta=zeta, challenge_x=x, enforce_fiat_shamir=False,
        ))
        # (b) DEFAULT refuses challenges it did not derive.
        self.assertFalse(verify_protocol1_ring(
            b"forge", self.base, self.e, self.f, self.g, bogus, forged,
            self.proof_params, zeta=zeta, challenge_x=x,
        ))
        # (c) Derived challenges also break the attacker's solved commitments.
        self.assertFalse(verify_protocol1_ring(
            b"forge", self.base, self.e, self.f, self.g, bogus, forged,
            self.proof_params,
        ))


if __name__ == "__main__":
    unittest.main()
