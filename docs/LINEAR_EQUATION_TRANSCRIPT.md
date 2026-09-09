# Linear-equation transcript (Gao Protocol 5 / body "Protocol 2")

`pqct.linear_equation_transcript` implements the ring-level machinery of
Gao's linear-equation satisfiability proof -- the piece that turns the
integer conservation relation into a commitment-level transcript with
the overflow-safe cycle-masking encoding.

## What it implements (paper lines 966-1027)

- `build_cycle_mask_commitment`: d_j = d~_j - 2*d~_{j+1} with
  d~_0 = d~_k = 0 (Gao eq.16), so <d, 2^k> = 0 EXACTLY over Z, and
  D = Com((d_j); r_d) under an HMC key.
- `compute_response_tail`: prover step 11, f_j = x*c_j + d_j for
  j in [1,k). f_0 is OMITTED from the transcript (the cycle mask makes
  it verifier-recoverable).
- `reconstruct_f0_over_integers`: verifier step 16, f_0 = -sum 2^j f_j
  computed over UNREDUCED integers (the paper's "run on R instead of
  R_q"), per polynomial coefficient.
- `f0_in_canonical_range`: step 17's "f_0 in R_q" gate -- coefficients
  must stay strictly inside the centered interval.
- `check_commitment_equation`: step 17's x*C + D = Com(f; z) in R_q.

## The overflow attack it defeats (verified by test)

A cheating c with sum_j 2^j c_j == q (zero mod q, NONzero over Z)
passes the mod-q commitment equation but makes the reconstructed
integer f_0 fall outside R_q's canonical range. With q=17, k=8,
c=(1,0,0,0,1,0,0,0): weighted sum 1+16=17=q, f_0 reconstructs to
-16, gate rejects. Honest c=(2,-1,0,...): f_0=+2, gate accepts.
Test: `test_overflow_cheat_is_caught_by_f0_range_gate`.

## What it does NOT do

- No rejection sampling for f_1/z yet (paper steps 12/14 with
  D_3,T_3 and phi_3; the existing Rej machinery covers phi_1/phi_2
  profiles only -- wiring a third stage is next).
- No composition with the balance transcript's Protocol 1 proofs into
  one end-to-end Protocol 5 run (steps 1/9 delegate to Pbin; that
  wiring is the follow-on).
- No soundness/SHVZK claim: Theorem 2's reduction is unimplemented.

## Boundary

Synthetic research only. Toy parameters; small-modulus fixtures are
deliberately chosen so the overflow gate is exercisable (q=12289 with
k=8 could never overflow -- noted in the test docstring). No
production, testnet, or mainnet use.

