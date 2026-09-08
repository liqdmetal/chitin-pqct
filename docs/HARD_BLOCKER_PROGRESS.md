# Hard-blocker progress

## Current verified state

- 151 tests pass.
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
  aggregated). Does NOT yet do the equation (38)-(45) three-transcript
  integer (mod-R) proof that the witness is exactly binary; see
  docs/BINARY_RELATION.md for the precise remaining gap.
- Chi-square goodness-of-fit tool applied to ACCEPTED honest samples
  (not just raw masks) confirmed `g`, `z_g`, AND `z_b,i` all fit their
  claimed D_{1,T1}/D_{2,T2} law (p=0.796/0.494/0.921, n=464). First
  two attempts falsely REJECTED z_g/z_b,i (p~1e-118) due to a
  gaussian_tail=9 vs true sigma~19.6 truncation bug in the TEST
  SCRIPT's own fixture, not in pqct itself -- root-caused (verified
  the truncated support was 90% flat at its own boundary) and fixed
  by widening tail to 60; see docs/GOODNESS_OF_FIT.md.

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
- Balance/range/conservation composition.
- External cryptanalysis.
- `Protocol1DistributionParameters` shares one `gaussian_tail` for both
  `t_profile` (small sigma) and `opening_profile` (larger sigma); tests
  must hand-tune a shared value, risking exactly the truncation bug
  found and fixed this session. Per-profile tails would remove that
  footgun.

## Boundary

The current artifacts support a synthetic equation/protocol POC and
falsification experiments only. They do not justify production use,
real keys, real balances, DERO integration, consensus changes,
testnet/mainnet deployment, or a "128-bit post-quantum" claim.
