# Hard-blocker progress

## Current verified state

- 259 tests pass.
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
- `pqct.transaction_proof.verify_transaction` is a WITNESS-FREE verifier
  for the composed proof: it recomputes every acceptance flag from public
  data (commitments, both proof sets, statement, key, signs) instead of
  trusting the prover's self-computed `*_ok` fields. 10 adversarial tests
  (swapped proofs, swapped/perturbed commitments, forged flags, flipped
  signs, dimension attacks) all rejected; honest tx accepted.
- `Protocol1DistributionParameters(auto_tail=True)` now derives each
  profile's support tail from its OWN sigma (~6*sigma via the shared
  `tail_for_sigma` helper), removing the shared-tail footgun that caused
  the false goodness-of-fit REJECT. Default stays off so existing callers
  are unaffected. Protocol 5's `_tail_for_sigma` delegates to the same
  single source.
- **CHALLENGE-INJECTION FORGERY closed in BOTH verifiers** (the most serious
  finding this session). `verify_linear_equation` (Protocol 5) and
  `verify_protocol1_ring` (Protocol 1) let a CALLER pass `challenge_x` (and,
  for P1, `zeta`). Whoever picks the challenge picks small responses first
  and solves the commitment equations backwards:
    P5: D = Com(f; z) - x*C  -- forges "conservation" for non-conserving sums
    P1: commitment_g = Com(weighted_g; z_b) - x*weighted_public
        commitment_f = Com(e; z_g) - x*commitment_e
        -- forges a "binary" proof for commitments encoding NO bits (7, 9, 3).
  Both forgeries were DEMONSTRATED to succeed (the tests assert the insecure
  path ACCEPTS, proving the vector real rather than theoretical), then closed:
  `enforce_fiat_shamir=True` is now the DEFAULT, deriving challenges from the
  transcript and rejecting any caller value that differs. The escape hatch
  `enforce_fiat_shamir=False` exists ONLY for the fixed-challenge research
  labs (SHVZK compare, family rewinding, cross-implementation) -- 4 call
  sites updated to opt out explicitly, each commented as not-a-verifier.
  Note: `verify_transaction` was never affected (it passes no challenges),
  which is itself evidence the witness-free verifier is the right boundary.
  14 new adversarial tests (13 P5 + 1 P1 injection); 273 total.
- Gao's published binding numbers reproduced from the transcribed
  Section 8 formulas: 2*gamma_bin = 2.864e14 (paper prints ~2.86e14) and
  Eq.(2) RHS = 4.100e14 (paper prints ~4.10e14). This RETIRES the earlier
  "instance trivially easy" finding as my own error: it used the unreduced
  Theorem 1 bound, a guessed phi_1=11 instead of the paper's 15, and
  double-counted d in Eq.(2). See docs/VERIFIED_LATTICE_ESTIMATE.md.

## Still open

- Complete intermediate integer/modular-lift accounting for every
  paper equation and response aggregation path.
- Exact discrete-Gaussian convention/statistical distance for D1/D2/D3
  (marginal comparison is now real-signal, not the birthday artifact).
- Full computational-binding reduction in the general (non-collision)
  case -- only collision-to-SIS and Eq.(2) are implemented.
- Extraction of the binary witness from all three transcripts: DONE
  (`pqct/three_transcript_extraction.py`, 17 tests). Two transcripts
  give only the divided difference y*b and CANNOT detect a cheating
  prover, because two points always fit a line. Three transcripts are
  overdetermined and add, all inversion-free (the ring has zero
  divisors, so challenge differences are not invertible):
    * the relaxed MASK, via x_b*g_a - x_a*g_b = -y*t (a plain divided
      difference discards this);
    * CROSS-CONSISTENCY (x1-x2)*(g0-g1) == (x0-x1)*(g1-g2), which fails
      for responses that are not affine in x -- verified by an attack
      test that perturbs only the third response, passes the pairwise
      check, and is caught only here;
    * a binary check B*(y-B) == 0 on the extracted relaxed value, which
      rejects a relaxed opening of a non-bit.
  Repeated challenges are REFUSED: y = 0 makes every check vacuous.
  Still not knowledge soundness -- no proof that every accepting
  adversary can be rewound into three such transcripts (that is the
  Fiat-Shamir/QROM item).
- SHVZK simulator distribution comparison with exact per-index
  rejection GATE components: the simulator now HAS a Lemma 6 abort
  stage (`pqct/simulator_rejection.py`,
  `simulate_protocol1_ring_with_abort`) that aborts at the
  witness-independent rate 1/mu(phi). The honest prover's empirical
  acceptance rate was measured against 1/mu across phi=1..32 and
  agrees (at the paper's phi=15: target 0.965069, measured 0.966500).
  Remaining: the per-index marginals are compared, but no proof that
  the two full transcript DISTRIBUTIONS are statistically close.
- Fiat-Shamir proof in the quantum random-oracle setting.
- Verified (not self-built) Module-SIS estimate: the REAL
  malb/lattice-estimator is installed, sandboxed (WSL user `pqct`,
  sage 10.7, internet-only, LAN-blocked, no sudo) and NOW RUNS TO
  COMPLETION. The blocker that stopped it was an mpmath/mpfr `erf`
  bug in the conda build ("Cannot convert mpz to
  sage.rings.integer.Integer"), worked around by patching
  `estimator.prob.gaussian_cdf` to stdlib `math.erf`; see
  `tools/sage_sis_estimate.py`. It reports 83-113 bits for a scalar
  bound reading, and the independent delta-criterion in
  `pqct/msis_hardness.py` gives 92-117 bits with delta agreeing to
  ~3e-4. Both sit BELOW the paper's claimed 128-bit level, which
  traces to the legacy delta=1.0045 <-> 128-bit mapping inherited
  from MatRiCT, not to an arithmetic error. What is STILL open is a
  cryptographic judgement, not tooling: (a) the exact M-SIS instance
  for HMC binding has MIXED per-column bounds that a single scalar
  length_bound cannot express, and (b) delta -> bits is a model
  choice. See docs/MSIS_HARDNESS.md and
  docs/VERIFIED_LATTICE_ESTIMATE.md. NOTE: an earlier
  "trivially easy by counting" verdict was MY error -- it evaluated
  the Gaussian heuristic at the full column count instead of the
  optimal sublattice dimension.
- Independent Rust implementation.
- Balance/range/conservation composition: integer oracle done
  (`balance_composition`); commitment-level composition done
  (`balance_transcript`, real Protocol 1 proofs + eq.(11) check).
  The ZK conservation proof (Gao Protocol 5, cycle masking over ring
  elements) is implemented end-to-end in `protocol5`, and Protocol 1 +
  Protocol 5 are composed over shared commitments in
  `transaction_proof`. The third rejection stage's D_3 convention is now
  RESOLVED against the paper: Protocol 2 steps 4-5 give d~_0 = d~_k = 0,
  d~_j ~ D_{3,T3} for j in [1,k), committed mask d_j = d~_j - 2*d~_{j+1};
  `derive_ring_cycle_mask` implements exactly this, and the prover samples at
  sigma = phi_3*T_3 = D_{3,T3}. The step-5 transform DERIVES step 17's factor
  3 (|d_j| <= 3*T3, tight at alternating signs, test-pinned), so
  6*phi_3*T_3*sqrt(d) = 2 * 3 * phi_3 * T_3 * sqrt(d) with only the Gaussian
  rejection-slack factor 2 unpinned. Remaining: all three rejection stages
  use finite-support Gaussian REFERENCES, not Gao's exact infinite laws --
  the same D1/D2 caveat (blocker item: exact statistical distance). Verifier
  norm bounds are confirmed to match the paper's step-17 formulas exactly
  (500-dpi transcription, test-pinned); what remains uncertified is the
  bit-security level (blocker item 5).
- External cryptanalysis.

## Boundary

The current artifacts support a synthetic equation/protocol POC and
falsification experiments only. They do not justify production use,
real keys, real balances, DERO integration, consensus changes,
testnet/mainnet deployment, or a "128-bit post-quantum" claim.
