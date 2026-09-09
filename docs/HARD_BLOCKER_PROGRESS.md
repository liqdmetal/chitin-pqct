# Hard-blocker progress

## Current verified state

- 238 tests pass.
- `compileall` passes for `pqct`, `tests`, and `tools`.
- `git diff --check` passes.
- `pip check` reports no broken requirements.
- Sampled Protocol 1 transcript generation, two-stage rejection,
  independent verification, pairwise extraction, fixed-zeta
  validation, and S=2 first-layer extraction are implemented.
- `pqct.protocol1_integer_trace` records unreduced coefficient-level
  operations beside modular ring calculations.
- `pqct.statistical_distance` provides conservative TV bounds for the
  finite reference sampler.
- `pqct.protocol1_rejection_audit` constructs the exact pre-aggregation
  Step 8/10 rejection tuples independently.
- `pqct.shvzk_empirical_stats.marginal_integer_stats` corrects the
  full-tuple TV=1 birthday-bound artifact: per-coefficient marginal
  TV is 0.05-0.08 for all three of `g`, `z_g`, `z_b,i` (see
  docs/SHVZK_COMPARISON.md), not ~1. Removed dead placeholder code
  (`_sample_protocol_rejection`) that always raised.
- `pqct.hmc_binding_reduction` mechanically derives a literal M-SIS
  solution from a real HMC collision and checks Gao Equation (2).
- `pqct.lattice_estimate` chains Eq.(2) -> BKZ blocksize -> core-SVP
  bits (self-built, cited-constants methodology; not the verified
  Albrecht/Player/Scott tool). Found and fixed a real dimensional bug:
  the toy `ParameterCandidate.n` conflates ring degree with SIS rank.
- `pqct.goodness_of_fit` adds a pure-stdlib chi-square goodness-of-fit
  test (regularized incomplete gamma, validated to 3e-15 vs scipy as a
  test-only oracle). `t_i` mask samples fit their own claimed
  `FiniteDiscreteGaussian` PMF (p=0.864, n=20000; see
  docs/GOODNESS_OF_FIT.md). This is self-consistency, not agreement
  with Gao's exact infinite D_sigma law.
- `pqct.protocol1_binary_relation.extract_binary_witness_row`: derives
  relaxed b_{i,j} from two accepting transcripts' g_{i,j}(x) values
  (divided difference, no unbatching needed -- g is never zeta-
  aggregated). `verify_binary_relation_equations_38_45` additionally
  implements the paper's equations (39),(41)-(45) as a bounded oracle
  over the TRUE witness (not yet a full extractor -- see
  docs/BINARY_RELATION.md for the precise remaining gap, notably the
  eq.(38)/(40) zeta-unbatching step and the zero-divisor gap between
  "D*u=0 in R" and "u=0").
- Chi-square goodness-of-fit tool applied to ACCEPTED honest samples
  (not just raw masks) confirmed `g`, `z_g`, AND `z_b,i` all fit their
  claimed D_{1,T1}/D_{2,T2} law (p=0.796/0.494/0.921, n=464). First
  two attempts falsely REJECTED z_g/z_b,i (p~1e-118) due to a
  gaussian_tail=9 vs true sigma~19.6 truncation bug in the TEST
  SCRIPT's own fixture, not in pqct itself -- root-caused (verified
  the truncated support was 90% flat at its own boundary) and fixed
  by widening tail to 60; see docs/GOODNESS_OF_FIT.md.
- `pqct.balance_composition` adds the corrector-free balance oracle
  (Gao Section 4): SignedAmount decomposition -> per-column c_j ->
  cycle-masked exact-zero response. Caught and fixed a real zip bug in
  the first build (see docs/BALANCE_COMPOSITION.md).
- `pqct.balance_transcript` composes the integer oracle with real HMC
  commitments and REAL sampled Protocol 1 binary proofs (per-amount,
  rejection-gated), plus the eq.(11) homomorphic combination check.
  Conservation itself is still checked as an exact integer relation
  against the witnesses, NOT yet a ZK Protocol 5 inner-product proof.
  See docs/BALANCE_TRANSCRIPT.md.
- `pqct.linear_equation_transcript` implements Gao Protocol 5's
  ring-level cycle-masking machinery: D=Com(d;r_d) with <d,2^k>=0 over
  Z, response tail f_j=x*c_j+d_j (f_0 omitted), integer-level f_0
  reconstruction, and the "f_0 in R_q" overflow gate. Test-verified
  discrimination: a cheat with sum 2^j c_j == q (0 mod q, nonzero over
  Z) is CAUGHT by the range gate; honest transcripts pass. See
  docs/LINEAR_EQUATION_TRANSCRIPT.md.
- `pqct.protocol5` is the end-to-end Protocol 5 prover/verifier: ring
  cycle mask, T3/T2' formulas, per-profile tails, two rejection stages
  with abort/retry, verifier never sees c or r_c. Test-verified: the
  mod-q cheat (+16+16-15=17=q at q=17) cannot produce an accepted
  proof; honest conserved transactions prove and verify. See
  docs/PROTOCOL5.md. Also fixed a real perf trap: FiniteDiscreteGaussian
  weights are now cached (tail~940 was recomputing ~240k Decimal exp()
  per sample, timing out 512-attempt runs).
- `pqct.transaction_proof` composes Protocol 1 (binary) + Protocol 5
  (conservation) over ONE shared commitment set, with the shared-
  commitment identity checked explicitly. Two rejection layers: prover-
  side fail-fast integer check (efficiency) + verifier-side f_0 range
  gate (soundness, witness-free). CLI demo
  `tools/demo_transaction_proof.py` runs honest/non-conserved/mod-q-cheat
  scenarios. See docs/TRANSACTION_PROOF.md.
- `pqct.paper_bounds` implements Gao's EXACT Theorem 1/2 bound formulas
  (gamma_bin, gamma_LE, q/2 precondition, relation bounds, mu/completeness
  error) transcribed from the 500-dpi PDF and unit-tested against hand
  values. `pqct.parameter_validation` composes them with the core-SVP
  estimator into one chain (params -> binding bound -> delta -> BKZ ->
  bits). Two honest findings: (1) the lab's TOY fixtures FAIL Theorem 1's
  own q/2 precondition (pinned by test), and (2) Gao's reported profile
  lands ~89 classical bits under OUR self-built estimator (not the
  verified tool), which is exactly why blocker item 5 still matters.
  See docs/PAPER_BOUNDS.md.
- Lemma 6 completeness validated QUANTITATIVELY: measured Protocol 1
  acceptance matches the paper's 1/(mu(phi1)mu(phi2)) within Wilson 95%
  CI at phi1=1,2,4 (tools/check_completeness_error.py). First numeric
  cross-check of a theorem claim against harness behavior. See
  docs/COMPLETENESS_ERROR.md.

## Still open

- Complete intermediate integer/modular-lift accounting for every
  paper equation and response aggregation path.
- Exact discrete-Gaussian convention/statistical distance for D1/D2/D3
  (marginal comparison is now real-signal, not the birthday artifact).
- Full computational-binding reduction in the general (non-collision)
  case -- only collision-to-SIS and Eq.(2) are implemented.
- Extraction of the binary witness from all three transcripts.
- SHVZK simulator distribution comparison with exact per-index
  rejection GATE components (the simulator now returns per-index
  `z_b,i` values and their marginal is compared, but it still has
  no Rej()-style acceptance/rejection stage to gate them through).
- Fiat-Shamir proof in the quantum random-oracle setting.
- Verified (not self-built) Module-SIS/Module-LWE estimate via the
  real `lattice-estimator` tool.
- Independent Rust implementation.
- Balance/range/conservation composition: integer oracle done
  (`balance_composition`); commitment-level composition done
  (`balance_transcript`, real Protocol 1 proofs + eq.(11) check).
  The ZK conservation proof (Gao Protocol 5, cycle masking over ring
  elements) is implemented end-to-end in `protocol5`, and Protocol 1 +
  Protocol 5 are composed over shared commitments in
  `transaction_proof`. Remaining: the third rejection stage's exact
  D_3 convention (finite-support reference only), and certified
  verifier norm bounds (currently research placeholders).
- External cryptanalysis.
- `Protocol1DistributionParameters` shares one `gaussian_tail` for both
  `t_profile` (small sigma) and `opening_profile` (larger sigma); tests
  must hand-tune a shared value, risking exactly the truncation bug
  found and fixed this session. `protocol5._tail_for_sigma` (~6*sigma
  per profile) is the demonstrated fix pattern; folding it back into
  Protocol1DistributionParameters remains to do.

## Boundary

The current artifacts support a synthetic equation/protocol POC and
falsification experiments only. They do not justify production use,
real keys, real balances, DERO integration, consensus changes,
testnet/mainnet deployment, or a "128-bit post-quantum" claim.
