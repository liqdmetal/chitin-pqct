# Transaction proof (Protocol 1 + Protocol 5 composed)

`pqct.transaction_proof` composes the two proven halves into one
transaction artifact over a SINGLE shared set of HMC bit commitments.

## Why composition was the gap

Before this, the two halves each committed bits INDEPENDENTLY:
- `balance_transcript` ran Protocol 1 binary proofs on its own B_i.
- `protocol5` proved conservation on its own separately-sampled B_i.

That is not a transaction: nothing tied the bits the binary proofs
covered to the bits the conservation proof used. A composed proof must
run BOTH over ONE commitment set, or the two halves prove facts about
different values.

## How it wires them together

`prove_transaction`:
1. Decomposes each signed amount to bits, samples ONE opening per
   amount, commits B_i = Com(bits_i; opening_i) once.
2. Runs Protocol 1 (`prove_protocol1_ring_sampled`) per amount on those
   shared (bits, opening, B_i) -- proves every amount's bits are binary.
3. Runs Protocol 5 (`prove_linear_equation`) with
   `openings_override=<the same openings>` so it commits to the SAME
   bits and proves sum_i lambda_i * a_i = 0 over Z.
4. Checks `conservation.bit_commitments == commitments` (the shared-
   commitment identity), re-verifies every Protocol 1 proof, and runs
   `verify_linear_equation` fresh. `accepted` requires all three.

`openings_override` on Protocol 5 is validated OUTSIDE the retry loop so
malformed input raises instead of being swallowed into "no accepted
transcript".

## Two rejection layers (do not conflate them)

1. **Prover-side fail-fast** (`prove_transaction`): computes
   `sum_j 2^j c_j` over the integers from the WITNESS up front; if it
   is nonzero, raises immediately rather than burning the P5 retry
   budget on an impossible proof. This is an efficiency guard, not a
   security mechanism -- it uses the secret amounts.

2. **Verifier-side cryptographic gate** (`verify_linear_equation`):
   reconstructs f_0 over unreduced integers from the PUBLIC transcript
   and rejects unless f_0 lies in R_q's centered range. This catches a
   mod-q cheat (sum 2^j c_j == q, i.e. 0 mod q but nonzero over Z)
   WITHOUT the witness. This is the real soundness backstop, tested in
   test_protocol5.py::Protocol5CheatTests.

The CLI demo shows both cheats rejected; at transaction level the
fail-fast (layer 1) fires first. Layer 2 is what protects a verifier
who does not hold the witness.

## Witness-free verifier (added after adversarial review)

`verify_transaction` recomputes every acceptance flag from PUBLIC data
only — commitments, both proof sets, statement, key, and signs. It never
reads the secret amounts or openings.

This matters because `prove_transaction`'s own `*_ok` fields are
self-computed: a dishonest prover controls them. Self-verification is
not verification. An outside verifier must run `verify_transaction`,
which re-checks:

1. dimensions (one commitment + one Protocol 1 proof per amount, correct
   row counts, bit_width == key message width == p5.k);
2. every Protocol 1 binary proof against ITS OWN commitment, with the
   per-amount domain-separated statement;
3. the Protocol 5 conservation proof (f_0 range gate, f/z norms,
   commitment equation);
4. signs == conservation.lambdas;
5. the shared-commitment identity, so the two halves cannot prove facts
   about different values.

`TransactionVerification.accepted` requires all of it. Per-gate results
are exposed (`binary_failures`, `conservation_gates`) so a rejection
says which check failed rather than just returning false.

## Adversarial coverage (10 tests)

`tests/test_transaction_proof_adversarial.py` — each case is an attack
that must be caught by recomputation, not by trusted flags:

- swapped Protocol 1 proofs (proof[1] := proof[0]) -> rejected, failure
  index reported
- swapped public commitments -> rejected (each proof binds wrong B_i)
- perturbed commitment set -> conservation rejected (shared identity)
- forged `*_ok=True` on the dataclass -> no effect, still rejected
- flipped signs -> signs_consistent false
- dropped proof / wrong bit_width / truncated commitment row /
  empty inputs -> dimensions_ok false
- honest tx -> accepted, all four conservation gates true

## Verified (5 prover tests + 10 adversarial + CLI demo)

- Honest conserved tx (+10 +6 -16): accepted; shared_commitments_ok,
  binary_ok (3 Protocol 1 proofs), conservation_ok all True; P5 accepted
  attempt 1.
- Shared-commitment identity: P5's commitments == the Protocol 1 ones.
- Non-conserved (+10 +6 -15 = 1): rejected by fail-fast.
- Reproducible from seed; empty seed rejected.
- CLI (`tools/demo_transaction_proof.py`) runs honest / non-conserved /
  mod-q cheat and prints per-gate verdicts.

## What it does NOT do

- No range proof on the corrector-free columns beyond the bit-width
  bound; no fee/authorization/replay/state binding; no recovery
  encryption. This is conservation + binaryness, not a full CT.
- Verifier norm bounds ARE the paper's own step-17 formulas
  (6*phi_3*T_3*sqrt(d) and 2*phi_2*T_2*sqrt(m*d)), transcribed at 500 dpi
  and test-pinned -- see docs/PROTOCOL5.md. What is NOT certified is the
  underlying bit-security level (blocker item 5).
- No soundness/SHVZK/Fiat-Shamir proof: Theorem 1/2 reductions and
  external cryptanalysis remain open (TESTNET_SCOPE Section 1).

## Boundary

Synthetic research only. No production, testnet, or mainnet use; no
real balances or keys. See docs/TESTNET_SCOPE.md.

