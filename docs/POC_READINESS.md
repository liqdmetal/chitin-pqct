# POC Readiness

## Current point

The isolated lab is ready for a **synthetic interactive Protocol 1 equation POC**.
It is not ready for a confidential-transaction POC, wallet POC, DERO POC, or
production cryptography.

## Ready now

- exact-ring equation reference;
- deterministic sampled synthetic transcripts;
- abort/retry experiment;
- independent raw-tuple equation oracle;
- cross-implementation hand-constructed vector checks;
- independent expected-vector comparisons for `E`, `F`, `G`, `g`, `z_g`, and `z_b`;
- adversarial sign-swapped transcript rejection;
- three-transcript second-layer extraction;
- S=2 first-layer relaxed-opening extraction;
- pairwise and reverse-pair consistency checks;
- explicit mutation and malformed-shape tests;
- conservative integer/canonical-representative audit;
- reproducible local test command.

## POC still needed

1. Add complete intermediate unreduced arithmetic tracing for `h`, `x h`,
   `x z_g`, challenge powers, and aggregate terms.
2. Add exact rejection/distribution diagnostics and bounded statistical-distance
   experiments.
3. Add proof-size, proving-time, verification-time, memory, and acceptance-rate
   measurements for toy and paper-shaped bookkeeping profiles.
4. Add a separate Rust implementation before treating the POC as a serious
   implementation result.
5. Complete HMC binding and the binary-witness extraction reduction.
6. Complete SHVZK distribution comparison and Fiat–Shamir analysis.

## Readiness estimate

- Equation-lab POC: **ready now**.
- Reproducible synthetic interactive extractor demo: **ready now**.
- Paper-faithful cryptographic POC: **not yet**; exact distributions, rejection
  proof, SHVZK, soundness, and parameters remain.
- Confidential transaction POC: **not yet**; amount representation, range,
  conservation, authorization, recovery, state, and replay layers are absent.
- Production/real-money use: **not approved**.
