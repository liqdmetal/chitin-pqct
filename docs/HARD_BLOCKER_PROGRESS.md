# Hard-blocker progress

## Current verified state

- 138 tests pass.
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
  TV is 0.05-0.08 (see docs/SHVZK_COMPARISON.md), not ~1.
- `pqct.hmc_binding_reduction` mechanically derives a literal M-SIS
  solution from a real HMC collision and checks Gao Equation (2).
- `pqct.lattice_estimate` chains Eq.(2) -> BKZ blocksize -> core-SVP
  bits (self-built, cited-constants methodology; not the verified
  Albrecht/Player/Scott tool). Found and fixed a real dimensional bug:
  the toy `ParameterCandidate.n` conflates ring degree with SIS rank.

## Still open

- Complete intermediate integer/modular-lift accounting for every
  paper equation and response aggregation path.
- Exact discrete-Gaussian convention/statistical distance for D1/D2/D3
  (marginal comparison is now real-signal, not the birthday artifact).
- Full computational-binding reduction in the general (non-collision)
  case -- only collision-to-SIS and Eq.(2) are implemented.
- Extraction of the binary witness from all three transcripts.
- SHVZK simulator distribution comparison with exact per-index
  rejection components (simulator still lacks that decomposition).
- Fiat-Shamir proof in the quantum random-oracle setting.
- Verified (not self-built) Module-SIS/Module-LWE estimate via the
  real `lattice-estimator` tool.
- Independent Rust implementation.
- Balance/range/conservation composition.
- External cryptanalysis.

## Boundary

The current artifacts support a synthetic equation/protocol POC and
falsification experiments only. They do not justify production use,
real keys, real balances, DERO integration, consensus changes,
testnet/mainnet deployment, or a "128-bit post-quantum" claim.
