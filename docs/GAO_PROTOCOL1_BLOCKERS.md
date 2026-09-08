# Gao Protocol 1 — Remaining Blockers

## Closed in the equation laboratory

- exact paper challenge-set shape recorded and sampled;
- degree `n-1`, Hamming weight, and infinity norm shape enforced;
- ring-valued Fiat–Shamir challenge codec added;
- transcript domains bind statement, parameters, key encodings, and commitments;
- `zeta` is derived before `E/F/G`; `x` is derived after them;
- both aggregate equations use ring powers `zeta^i`;
- challenge multiplication is negacyclic ring multiplication;
- E/F/G dimensions match one ring element per bit or bit column;
- per-index openings are aggregated to the single `z_b` sent by Protocol 1;
- paper-shaped `T1`, `T2`, and response bounds are computed explicitly;
- finite-support box and discrete-Gaussian reference samplers added;
- both rejection stages use `gamma = phi*T` and the paper's exponent;
- sampled prover performs deterministic abort-and-retry;
- accepted sampled transcripts self-verify through the independent verifier;
- mutation, dimension, reproducibility, and multi-seed challenge tests pass;
- independent arithmetic oracle remains separate from the protocol path.

## Still open — not negotiable for a security claim

1. **Distribution exactness:** finite-support reference Gaussians are not yet a proof of the paper's exact discrete-Gaussian convention or statistical-distance target.
2. **Constant-time implementation:** the current inverse-CDF sampler and Decimal arithmetic are laboratory-only.
3. **Soundness:** `pqct.protocol1_family` now generates and audits the paper's S=2 two-level interactive extraction path, checks relaxed openings for `B`, `G`, `E`, and `F`, and runs the S=2 first-layer extractor without inversion. The complete paper reduction, HMC binding step, non-invertible challenge analysis under production parameters, full intermediate norm/modular-lift proof, and general S proof remain open. Standalone extraction can now accept explicit fixed-`zeta` metadata; without metadata, the API cannot prove how externally supplied transcripts were generated.
4. **SHVZK:** an equation-level simulator now exists in `pqct.protocol1_simulator`; statistical closeness, hiding reduction, response-distribution matching, and Fiat–Shamir treatment remain open.
5. **Concrete parameters:** run a recognized Module-SIS/Module-LWE estimator with actual dimensions and failure targets.
6. **Protocol composition:** implement and review the linear-equation/balance proof, range policy, integer-conservation rule, authorization, state binding, and balance-recovery encryption.
7. **External review:** university or equivalent independent cryptanalysis remains required before money, wallet, consensus, or production use.

## POC boundary

The equation-lab POC is ready: deterministic synthetic transcripts, extraction, and a structurally independent raw-tuple oracle now exist. The paper-faithful cryptographic POC is not ready until exact distributions, rejection distance, soundness, SHVZK, Fiat–Shamir, and parameters are reconciled. A confidential-transaction POC additionally needs amount, range, conservation, authorization, recovery, state, and replay layers.

The lab has crossed the equation/sampling/rejection boundary for synthetic experiments. It has **not** crossed the cryptographic-security boundary.
