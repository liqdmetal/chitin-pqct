import unittest

from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.hmc import HMCKey, bounded_ring_element
from pqct.protocol1_simulator import SimulationError, simulate_protocol1_ring
from pqct.ring_commitment import ToyParameters


class Protocol1SimulatorTests(unittest.TestCase):
    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=1)
        r = lambda values: bounded_ring_element(values, self.params)
        self.r = r
        self.base = HMCKey(
            G_r=((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
            G_m=((r((1, 0, 0, 0, 0, 0, 0, 0)), r((0, 1, 0, 0, 0, 0, 0, 0))),),
            params=self.params,
        )
        self.e = HMCKey(
            G_r=((r((1, 0, 0, 0, 0, 0, 0, 0)),),),
            G_m=(tuple(r((1, 0, 0, 0, 0, 0, 0, 0)) for _ in range(4)),),
            params=self.params,
        )
        self.f = self.e
        self.g = self.base
        self.bits = (
            (r((0, 0, 0, 0, 0, 0, 0, 0)), r((1, 0, 0, 0, 0, 0, 0, 0))),
            (r((1, 0, 0, 0, 0, 0, 0, 0)), r((0, 0, 0, 0, 0, 0, 0, 0))),
        )
        self.openings = ((r((2, 0, 0, 0, 0, 0, 0, 0)),), (r((3, 0, 0, 0, 0, 0, 0, 0)),))
        self.commitments = tuple(
            self.base.commit(vector, opening)
            for vector, opening in zip(self.bits, self.openings)
        )
        self.proof_params = RingProtocol1Parameters(2, 1, 1000, 1000, 1000)
        self.zeta = r((2, 1, 0, 0, 0, 0, 0, 0))
        self.challenge = r((3, 0, 1, 0, 0, 0, 0, 0))
        self.responses = (
            (r((1, 0, 0, 0, 0, 0, 0, 0)), r((2, 0, 0, 0, 0, 0, 0, 0))),
            (r((3, 0, 0, 0, 0, 0, 0, 0)), r((4, 0, 0, 0, 0, 0, 0, 0))),
        )
        self.zg = (r((2, 0, 0, 0, 0, 0, 0, 0)),)
        self.zb_components = ((r((2, 0, 0, 0, 0, 0, 0, 0)),), (r((3, 0, 0, 0, 0, 0, 0, 0)),))
        self.zb = (self.zb_components[0][0].add(self.zeta.mul(self.zb_components[1][0])),)
        self.e_randomness = (r((2, 0, 0, 0, 0, 0, 0, 0)),)

    def test_simulator_satisfies_equations_for_fixed_challenge(self):
        simulated = simulate_protocol1_ring(
            b"sim-statement", self.base, self.e, self.f, self.g,
            self.commitments, self.zeta, self.challenge,
            self.responses, self.zg, self.zb, self.proof_params,
            commitment_e_randomness=self.e_randomness,
            response_zb_components=self.zb_components,
        )
        proof = simulated.proof
        weighted_public = self.commitments[0][0].add(
            self.zeta.mul(self.commitments[1][0])
        )
        weighted_response = tuple(
            self.responses[0][column].add(self.zeta.mul(self.responses[1][column]))
            for column in range(2)
        )
        lhs_g = self.challenge.mul(weighted_public).add(proof.commitment_g[0])
        rhs_g = self.g.commit(weighted_response, self.zb)[0]
        self.assertEqual(lhs_g, rhs_g)
        h = tuple(
            value.mul(self.challenge.sub(value))
            for row in self.responses
            for value in row
        )
        lhs_e = self.challenge.mul(proof.commitment_e[0]).add(proof.commitment_f[0])
        rhs_e = self.e.commit(h, self.zg)[0]
        self.assertEqual(lhs_e, rhs_e)

    def test_dimension_mutation_rejected(self):
        with self.assertRaises(SimulationError):
            simulate_protocol1_ring(
                b"s", self.base, self.e, self.f, self.g, self.commitments,
                self.zeta, self.challenge, self.responses, (), self.zb,
                self.proof_params,
                commitment_e_randomness=self.e_randomness,
                response_zb_components=self.zb_components,
            )


if __name__ == "__main__":
    unittest.main()
