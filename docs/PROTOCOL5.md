# Protocol 5 end-to-end (linear-equation satisfiability)

`pqct.protocol5` implements Gao's Protocol 5 (body text "Protocol 2",
lines 966-1027) end-to-end at ring level: signed-amount conservation
as a commitment-level, rejection-gated, verifier-private protocol run.

## What it does

- `derive_ring_cycle_mask`: ring-valued telescoping mask
  d_j = d~_j - 2*d~_{j+1} (d~_0 = d~_k = 0), so sum_j 2^j d_j = 0
  COEFFICIENTWISE over Z. Generalizes Gao eq.(16) from integer scalars
  to full ring elements (the existing cycle_masking module is scalars
  only). Verified by ring_cycle_mask_weighted_sum_is_zero.
- `compute_t3` / `Protocol5Parameters`: T3 = max(sign sums)*p*sqrt(wk)
  per paper step 2; T2' = B*w*p*sqrt(3md); verifier f/z bounds are
  explicit RESEARCH bounds in the paper's 6*phi3*T3*sqrt(d) style,
  flagged as not independently re-derived.
- Per-profile Gaussian tails (~6*sigma each) via _tail_for_sigma:
  kills the shared-tail footgun flagged in HARD_BLOCKER_PROGRESS.
  Also: FiniteDiscreteGaussian weights/total_weight are now cached at
  construction (perf fix -- a 512-attempt run with tail~940 was
  recomputing ~240k Decimal exp() calls per sample before this).
- `prove_linear_equation`: decompose amounts -> commit B_i = Com(b_i;
  r_b,i) with r_b,i from S_B^m -> c_j columns + r_c = sum lam_i r_b,i
  -> sample d~ (D_3,T_3 shape) -> D = Com(d; r_d) -> FS challenge x
  bound to statement + B_i's + D -> f_j = x*c_j + d_j for j>=1 (f_0
  OMITTED) -> Rej(phi3,T3) -> z = x*r_c + r_d -> Rej(phi2,T2') ->
  abort/retry with fresh attempt seeds -> self-verify before returning.
- `verify_linear_equation`: never sees c or r_c. Computes
  C = sum lam_i B_i locally (eq.11), reconstructs f_0 over UNREDUCED
  integers, gates: f_0 in R_q range (the overflow/soundness gate),
  f/z norms, x*C + D = Com((f_0,f_1..); z). Per-gate booleans exposed
  so failures are diagnosable, not just a bool.

## Verified discrimination (9 tests)

The soundness crux: a transaction that balances mod q but NOT over the
integers must be rejected. Test fixture (q=17, k=5):

```text
honest  +10 +6 -16 = 0 over Z:      conserved=True, prover accepted
                                     attempt 1, all 4 verifier gates pass
cheat   +16 +16 -15 = 17 = q (mod q == 0, over Z == 17):
                                     conserved=False, weighted_sum=17=q,
                                     prover REFUSES accepted proof
```

For the cheat, f_0 = -17*x reconstructs with coefficients +/-34, far
outside q=17's centered range (-8,8], so the f_0-in-R_q gate kills it on
every attempt (deterministic, not flaky -- verified the algebra).

Also tested: ring cycle-mask weighted-sum == 0, reproducibility from
seed, Fiat-Shamir challenge derivation when verifier gets no explicit x,
tampered response tail rejected, sign_max/T3 helpers.

## What it does NOT do

- Protocol 1 binary proofs (Pbin, steps 1/9) are NOT run here; this
  proves conservation given committed bits. Composing the per-amount
  binary proofs (balance_transcript) with this into one Protocol 5 run
  is the follow-on.
- No soundness/SHVZK claim: Theorem 2's reduction is unimplemented and
  needs external cryptanalysis. Rejection stages use finite-support
  reference Gaussians, not the paper's exact D_3.
- Toy parameters; verifier norm bounds are research placeholders, not
  certified.

## Boundary

Synthetic research only. No production, testnet, or mainnet use. See
docs/TESTNET_SCOPE.md for what a testnet would actually require.
