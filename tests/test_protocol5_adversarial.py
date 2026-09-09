"""Adversarial tests for the Protocol 5 conservation verifier.

Each case is an attack on one of the four gates or on the transcript
binding. A verifier that recomputes from public data must reject all of
them; the honest case must still accept.
"""

import unittest
from decimal import Decimal

from pqct.balance_composition import SignedAmount, decompose_unsigned
from pqct.hmc import bounded_ring_element
from pqct.matrix_generation import generate_hmc_key
from pqct.protocol5 import (
    Protocol5Error,
    Protocol5Proof,
    compute_t3,
    protocol5_params_for_lambdas,
    prove_linear_equation,
    reconstruct_f0_over_integers,
    verify_linear_equation,
)
from pqct.ring_challenge import challenge_ring_element
from pqct.ring_commitment import RingElement, ToyParameters
from pqct.challenge import sample_sparse_challenge


class Protocol5AdversarialTests(unittest.TestCase):
    def unit(self):
        """Ring element with a single 1 in coefficient 0, full width."""
        return bounded_ring_element((1,) + (0,) * (self.params.n - 1), self.params)

    def setUp(self):
        self.params = ToyParameters(n=8, q=12289, k=5)
        self.seed = b"p5-adv"
        self.m, self.k = 2, 5
        self.key = generate_hmc_key(self.seed + b"|key", self.params, self.m, self.k)
        self.amounts = (SignedAmount(10, 1), SignedAmount(6, 1), SignedAmount(16, -1))
        self.signs = tuple(a.sign for a in self.amounts)
        self.statement = b"p5-adv-statement"
        self.p5 = protocol5_params_for_lambdas(
            self.signs, p=2, w=4, k=self.k, B=1, m=self.m, d=8,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )
        self.result = prove_linear_equation(
            seed=self.seed, statement=self.statement, key=self.key,
            amounts=self.amounts, bit_width=self.k, p5=self.p5,
            phi2=Decimal("4"), phi3=Decimal("4"),
        )

    def _verify(self, *, proof=None, lambdas=None, statement=None,
                bit_commitments=None, challenge_x=None):
        return verify_linear_equation(
            statement=statement if statement is not None else self.statement,
            key_c=self.key,
            bit_commitments=(
                bit_commitments if bit_commitments is not None
                else self.result.bit_commitments
            ),
            lambdas=tuple(lambdas) if lambdas is not None else self.signs,
            proof=proof if proof is not None else self.result.proof,
            p5=self.p5,
            challenge_x=challenge_x,
        )

    def test_honest_proof_accepts_all_four_gates(self):
        v = self._verify()
        self.assertTrue(v.f0_in_range)
        self.assertTrue(v.f_norms_ok)
        self.assertTrue(v.z_norm_ok)
        self.assertTrue(v.commitment_equation_ok)
        self.assertTrue(v.accepted)

    def test_tampered_commitment_d_rejected(self):
        rows = list(self.result.proof.commitment_d)
        rows[0] = rows[0].add(self.unit())
        forged = Protocol5Proof(
            commitment_d=tuple(rows),
            response_tail=self.result.proof.response_tail,
            response_z=self.result.proof.response_z,
        )
        v = self._verify(proof=forged)
        self.assertFalse(v.commitment_equation_ok)
        self.assertFalse(v.accepted)

    def test_tampered_response_tail_rejected(self):
        tail = list(self.result.proof.response_tail)
        tail[0] = tail[0].add(self.unit())
        forged = Protocol5Proof(
            commitment_d=self.result.proof.commitment_d,
            response_tail=tuple(tail),
            response_z=self.result.proof.response_z,
        )
        v = self._verify(proof=forged)
        self.assertFalse(v.accepted)

    def test_tampered_response_z_rejected(self):
        z = list(self.result.proof.response_z)
        z[0] = z[0].add(self.unit())
        forged = Protocol5Proof(
            commitment_d=self.result.proof.commitment_d,
            response_tail=self.result.proof.response_tail,
            response_z=tuple(z),
        )
        v = self._verify(proof=forged)
        self.assertFalse(v.commitment_equation_ok)
        self.assertFalse(v.accepted)

    def test_swapped_commitment_set_rejected(self):
        commits = list(self.result.bit_commitments)
        commits[0], commits[1] = commits[1], commits[0]
        v = self._verify(bit_commitments=tuple(commits))
        self.assertFalse(v.accepted)

    def test_different_statement_rejected(self):
        """FS binding: a proof for one statement must not verify under another."""
        v = self._verify(statement=b"a-different-statement")
        self.assertFalse(v.commitment_equation_ok)
        self.assertFalse(v.accepted)

    def test_nonconserving_amounts_rejected_by_prover(self):
        bad = (SignedAmount(16, 1), SignedAmount(16, 1), SignedAmount(15, -1))
        with self.assertRaises(Protocol5Error):
            prove_linear_equation(
                seed=self.seed, statement=self.statement, key=self.key,
                amounts=bad, bit_width=self.k, p5=self.p5,
                phi2=Decimal("4"), phi3=Decimal("4"),
            )

    def test_lambdas_inconsistent_with_p5_params_rejected(self):
        """omega_l1/account_count must match the public lambdas, else the
        T2'/z bound would be computed from a different relation.

        (1,1,-1) has L1 = 3; (2,1,-1) has L1 = 4, so reusing the same p5
        parameter set with different lambdas must be refused.
        """
        with self.assertRaises(Protocol5Error):
            self._verify(lambdas=(2, 1, -1))
        # A different account count must also be refused.
        with self.assertRaises(Protocol5Error):
            self._verify(lambdas=(1, 1))

    def test_out_of_range_f0_fails_range_gate(self):
        """A response tail implying f0 outside R_q's centered range must fail
        the integer lift gate even if it is modularly consistent."""
        tail = tuple(
            bounded_ring_element((self.params.q // 2 + 1,) + (0,) * (self.params.n - 1), self.params)
            for _ in range(self.k - 1)
        )
        forged = Protocol5Proof(
            commitment_d=self.result.proof.commitment_d,
            response_tail=tail,
            response_z=self.result.proof.response_z,
        )
        v = self._verify(proof=forged)
        self.assertFalse(v.f0_in_range)
        self.assertFalse(v.accepted)

    def test_inflated_z_norm_rejected(self):
        """z with an out-of-bound norm must fail the z gate."""
        big = tuple(
            bounded_ring_element((self.params.q // 2,) + (0,) * (self.params.n - 1), self.params)
            for _ in range(self.m)
        )
        forged = Protocol5Proof(
            commitment_d=self.result.proof.commitment_d,
            response_tail=self.result.proof.response_tail,
            response_z=big,
        )
        v = self._verify(proof=forged)
        self.assertFalse(v.z_norm_ok)
        self.assertFalse(v.accepted)

    def test_mismatched_row_count_raises(self):
        with self.assertRaises(Protocol5Error):
            self._verify(proof=Protocol5Proof(
                commitment_d=self.result.proof.commitment_d[:-1],
                response_tail=self.result.proof.response_tail,
                response_z=self.result.proof.response_z,
            ))

    def test_wrong_tail_length_raises(self):
        with self.assertRaises(Protocol5Error):
            self._verify(proof=Protocol5Proof(
                commitment_d=self.result.proof.commitment_d,
                response_tail=self.result.proof.response_tail[:-1],
                response_z=self.result.proof.response_z,
            ))

    def test_injected_challenge_cannot_forge_conservation(self):
        """FORGERY ATTEMPT against a caller-supplied challenge.

        The commitment equation is x*C + D = Com(f; z). If a caller picks x,
        they pick small f and z FIRST and set D = Com(f; z) - x*C. The
        equation then holds for ANY public commitments, including
        non-conserving ones, and the norm gates pass.

        This test shows (a) the attack genuinely forges when FS enforcement is
        disabled -- so the vector is real, not theoretical -- and (b) the
        DEFAULT verifier refuses an x it did not derive.
        """
        # Non-conserving public values: +3 +5 -1 = 7 != 0.
        forged_amounts = (SignedAmount(3, 1), SignedAmount(5, 1), SignedAmount(1, -1))
        bit_commitments = []
        for index, amount in enumerate(forged_amounts):
            bits = decompose_unsigned(abs(amount.value), self.k)
            col = tuple(
                bounded_ring_element((bit,) + (0,) * (self.params.n - 1), self.params)
                for bit in bits
            )
            r_b = tuple(
                bounded_ring_element((index + 1,) + (0,) * (self.params.n - 1), self.params)
                for _ in range(self.m)
            )
            bit_commitments.append(self.key.commit(col, r_b))
        bit_commitments = tuple(bit_commitments)

        # C = sum lambda_i B_i over the public commitments.
        c_commitment = tuple(RingElement.zero(self.params) for _ in range(self.key.ring_rows))
        for lam, row in zip(self.signs, bit_commitments):
            c_commitment = tuple(
                total.add(value.scalar_mul(lam))
                for total, value in zip(c_commitment, row)
            )

        x = challenge_ring_element(
            sample_sparse_challenge(self.seed + b"|chosen-x", self.params, 4, 2)
        )
        # The verifier does NOT take f_0 from the proof -- it reconstructs it
        # over the integers as f_0 = -sum_{j>=1} 2^j * f_j. So the forger must
        # pick the TAIL, let f_0 be forced, then solve D for that exact f.
        f_tail = tuple(
            bounded_ring_element((1,) * self.params.n, self.params)
            for _ in range(self.k - 1)
        )
        f0_int = reconstruct_f0_over_integers(f_tail)
        f0_element = RingElement.from_coeffs(
            tuple(value % self.params.q for value in f0_int), self.params
        )
        f = (f0_element, *f_tail)
        z = tuple(RingElement.zero(self.params) for _ in range(self.m))
        commit_fz = self.key.commit(f, z)
        d_rows = tuple(
            commit_row.sub(x.mul(c_row))
            for commit_row, c_row in zip(commit_fz, c_commitment)
        )
        forged = Protocol5Proof(commitment_d=d_rows, response_tail=f_tail, response_z=z)

        # (a) With FS enforcement OFF the forgery is accepted -- proving the
        #     vector is real and why the default must be ON.
        insecure = verify_linear_equation(
            statement=self.statement, key_c=self.key,
            bit_commitments=bit_commitments, lambdas=self.signs,
            proof=forged, p5=self.p5, challenge_x=x,
            enforce_fiat_shamir=False,
        )
        self.assertTrue(insecure.commitment_equation_ok,
                        "forgery should satisfy the equation when x is attacker-chosen")
        self.assertTrue(insecure.accepted)

        # (b) The DEFAULT verifier refuses an x it did not derive.
        with self.assertRaises(Protocol5Error) as context:
            verify_linear_equation(
                statement=self.statement, key_c=self.key,
                bit_commitments=bit_commitments, lambdas=self.signs,
                proof=forged, p5=self.p5, challenge_x=x,
            )
        self.assertIn("Fiat-Shamir", str(context.exception))

        # (c) Defaulting to the derived challenge also rejects: D was solved
        #     for the attacker's x, not the FS-derived one.
        honest_x = self._verify(
            proof=forged, bit_commitments=bit_commitments, lambdas=self.signs,
        )
        self.assertFalse(honest_x.accepted)


if __name__ == "__main__":
    unittest.main()
