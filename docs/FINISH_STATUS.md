# PQ-CT Finish Status

## Implemented reference layers

- Published construction selected: Gao et al., IACR 2021/1674.
- PDF equations recovered and transcribed.
- Exact cycle masking and integer relation checks.
- HMC-shaped commitment interface:
  `C = G_r*r + G_m*m`.
- HMC-backed reduced transcript.
- HMC-backed Protocol-1-shaped binary transcript with `E`, `F`, and `G` objects.
- Domain-separated transcript hashing.
- Explicit response/opening bounds in the toy harness.
- Distribution-independent rejection-sampling arithmetic.
- Mutation tests for statement binding, tampering, nonbinary witnesses, and modular wraparound.

## Hard boundary

The implementation is still a **research reference harness**, not a secure cryptocurrency primitive. The following are intentionally not claimed complete:

- production HMC/UMC parameter generation;
- exact paper discrete-Gaussian samplers `D1`, `D2`, `D3`;
- paper-complete ring-valued Fiat–Shamir transcript binding;
- rejection-sampling calibration for a concrete parameter set;
- Module-SIS security estimate;
- formal special-soundness/SHVZK proof independently checked;
- balance-recovery encryption;
- authorization, replay, double-spend, or account-state consensus integration.

## Verification snapshot

The isolated lab currently passes the full Python suite with 45 tests and compiles successfully. The DERO repository was not modified by this work.

Passing tests are evidence that the implemented reference equations and selected rejection cases execute as intended. They are not evidence of cryptographic security.

## University handoff package

Before requesting external review, package:

1. `FORMAL_SPEC.md`, `SECURITY_GAMES.md`, and `THREAT_MODEL.md`;
2. the downloaded paper and source commit identifiers;
3. the slow reference implementation and fixed test vectors;
4. an independent second implementation;
5. parameter-estimator output and completeness/soundness accounting;
6. adversarial test and mutation reports;
7. a list of unresolved assumptions and known limitations.
