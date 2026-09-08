# Hard-Blocker Resource Plan

## Bottom line

The current desktop is enough for the **reference laboratory** and most of the
falsification work. It is not enough to turn the construction into a credible
secure-money claim by itself. The genuinely hard work needs independent people,
independent implementations, formal/probabilistic tooling, and concrete lattice
estimation.

## What each blocker needs

| Blocker | Minimum serious resource | Deliverable that counts | Current desktop role |
|---|---|---|---|
| Exact discrete-Gaussian/rejection analysis | Cryptographer who has implemented lattice Gaussian samplers; Sage/Python/MPFR or equivalent arbitrary precision; paper PDF and author code pinned | Exact convention table, sampler proof/known-answer vectors, tail and statistical-distance calculation, measured acceptance with confidence intervals | Reference oracle, vectors, exhaustive tiny cases |
| Constant-time sampler | C/Rust implementer familiar with constant-time arithmetic, fixed-point/MPFR test oracle, sanitizers, timing harness, multiple CPU classes | Constant-time design review, differential output tests, timing-distribution report, no secret-dependent branches/table lookups | Slow oracle and differential target |
| `(S,3)` relaxed-opening soundness | Lattice/ZK proof researcher, independent notation derivation, symbolic algebra (Sage/Mathematica/SymPy), tiny-ring exhaustive extractor | Written extractor for `S<=2`, explicit relaxed relation and norm bounds, non-invertible challenge-difference treatment, adversarial transcript tests | Transcript generator and bounded exhaustive oracle |
| SHVZK | ZK researcher plus statistical testing; simulator and honest-prover implementations kept separate; Python/Julia/R for distribution tests | Simulator code, coupling/distribution argument, TV-distance/chi-square tests with power analysis, failure interpretation | Synthetic transcripts and mutations |
| Concrete Module-SIS/LWE estimate | Lattice estimator expertise; pinned estimator version and assumptions; Sage/Python; exact `(n,m,q,B)` and ring model | Parameter table, estimator input/output, conservative security interpretation, failure probabilities, no unsupported 128-bit claim | Candidate generation and reproducibility |
| Full balance/range composition | Protocol designer plus lattice-proof reviewer; integer/ring relation model; property/fuzz testing | Complete statement/witness/verifier spec, conservation-over-integers proof, range/overflow/replay tests, composition argument | Shadow-ledger relation tests |
| Authorization/state/recovery | PQ signature/KEM engineer, wallet/key-management reviewer, threat model for compromise/recovery; HSM/test-key discipline | Non-strippable authorization, domain/nonce/state binding, recovery and rotation spec, downgrade/replay tests | No real keys; synthetic test fixtures only |
| Independent implementation | Second team or at least a separate language/codebase with no shared helpers; Rust/C reference; independent vector generation | Cross-language known-answer agreement, mutation/differential results, review of serialization and arithmetic | Python reference and oracle |
| Side-channel/engineering | Constant-time reviewer, dudect/ctgrind-like timing tools, sanitizers, fuzzers, CPU diversity | Timing report, memory/UB report, parser/verifier fuzz corpus and minimized crashes | Fuzz target scaffolding and golden vectors |
| External cryptanalysis | Two or more reviewers with lattice/ZK credentials; paid narrow-scope review; no author conflict | Written severity-ranked report covering equations, reductions, parameters, implementation, and adaptation | Assemble review package; do not treat internal review as substitute |

## People required

A credible minimum team is **four distinct skill sets**, not four generic coders:

1. **Lattice cryptographer:** Module-LWE/SIS, HMC/UMC, Gaussian sampling,
   smoothing parameters, rejection sampling.
2. **ZK proof researcher:** special soundness, relaxed openings, SHVZK,
   Fiat–Shamir/quantum random-oracle limitations, composition.
3. **Independent systems implementer:** Rust/C, canonical serialization,
   constant-time behavior, fuzzing, differential testing.
4. **Protocol/security reviewer:** account state, authorization, recovery,
   replay, integer conservation, threat-model and migration review.

One person can cover more than one role, but independence is lost when the same
person designs, implements, and signs off on every layer.

## Compute and tooling

### Required now

- Existing Windows workstation: sufficient for small-ring exhaustive tests,
  reference sampling, transcript mutation, and documentation.
- Separate clean machine or VM for the second implementation and reproducible
  builds.
- Git-committed toolchain lockfiles and paper/source hashes.
- Arbitrary-precision arithmetic: MPFR/mpmath/SageMath; do not use binary
  floating point for final tail claims.
- Property/fuzz tools: Hypothesis, AFL++/libFuzzer or cargo-fuzz, sanitizers.
- Statistical tooling: Python/NumPy/SciPy or R, with pre-registered sample
  sizes and confidence intervals.
- Lattice estimator: pinned upstream estimator/repository and documented model.

### Useful but not the bottleneck

- More CPU cores for rejection Monte Carlo and fuzzing.
- 32–128 GB RAM for large transcript batches and estimator sweeps.
- CI on Linux and Windows, plus at least two CPU microarchitectures.
- GPU is optional. It helps batch Monte Carlo and fuzz workloads but does not
  replace a proof researcher, estimator, or independent implementation.

## Budget bands

These are planning bands, not quotes and not a promise of vendor availability.
They exclude production integration, wallet custody, and consensus work.

| Work package | Lean serious band |
|---|---:|
| Independent implementation and differential vectors | $15k–$40k |
| Lattice parameter review/estimation | $20k–$60k |
| ZK soundness/SHVZK review | $20k–$60k |
| Constant-time and side-channel review | $10k–$30k |
| University/narrow external study support | $5k–$25k |
| **External-review subtotal** | **$65k–$192k** |
| Research lab / tooling reserve | $0k–$2k |
| **Full planning band** | **$70k–$217k** |

A university collaboration may reduce cash cost but usually increases calendar
and coordination cost. It does not make the internal proof obligations vanish.

## Recommended order

### Gate 1 — no-money, desktop-plus-independent-code

- Freeze paper, source commit, notation table, and exact distribution convention.
- Finish the slow reference sampler with arbitrary-precision tail accounting.
- Write the `S<=2` extractor on paper and test it against bounded tiny rings.
- Build the independent Rust implementation and cross-check vectors.
- Run parser/verifier fuzzing and mutation campaigns.

### Gate 2 — specialist review

- Send only the narrow Gao Protocol 1 package to a lattice/ZK reviewer.
- Ask for line-by-line criticism of equations, dimensions, rejection parameters,
  relaxed relation, and security reduction.
- Do not ask “is this secure?” Ask “which exact claim fails, under which
  assumption, and what correction is required?”

### Gate 3 — parameter and simulator package

- Implement the independent SHVZK simulator.
- Run estimator sweeps over candidate dimensions and failure targets.
- Publish a table of proof size, acceptance, prover/verifier cost, memory, and
  statistical test results.

### Gate 4 — only then composition

- Add balance/range/integer conservation and authorization/state/recovery.
- Keep it as a shadow ledger with synthetic values.
- Obtain a second review specifically on composition and account migration.

## Stop conditions

Stop and redesign rather than “punch through” if any of these occur:

- the paper's notation remains ambiguous after PDF/source reconciliation;
- the extractor requires an unstated invertibility assumption;
- the rejection majorant is only checked at sampled points rather than proven
  over the full shift domain;
- the simulator is algebraically accepting but distributionally untested;
- the estimator model does not match the ring/key distribution;
- the second implementation shares the same bug or test vectors;
- reviewers cannot reproduce the claimed bounds from the committed artifacts.

## Current answer

We do **not** need a bigger GPU first. We need an independent lattice/ZK brain,
a second implementation, arbitrary-precision distribution analysis, and a pinned
estimator. The desktop can carry the lab until those resources are secured.
