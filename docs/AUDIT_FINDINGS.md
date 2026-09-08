# Internal Audit Findings — Independent Eyes

**Decision:** NO-GO for production; GO for synthetic research only.

## Closed or narrowed

### F-001 — Protocol equation mismatch

The old scalar/batched helper was not Gao Protocol 1. A separate ring-valued path now exists. It derives the pre-commitment aggregation challenge `zeta`, uses ring powers `zeta^i`, then derives the response challenge `x` after `E/F/G`.

### F-002 — Missing rejection path

A finite-support reference sampler, exact paper-shaped rejection exponent, two-stage abort/retry wrapper, and self-verification path now exist. This closes the **laboratory wiring** gap only; it does not establish the paper's infinite discrete-Gaussian statistical-distance theorem.

### F-003 — Aggregate/index confusion

The implementation now keeps `z_{b,i}` per index internally and emits the single Protocol 1 aggregate `z_b = sum_i zeta^i z_{b,i}`. The verifier checks that aggregate against the weighted public commitment.

### F-004 — Incorrect coefficientwise challenge multiplication

The rejection harness now multiplies each ring block negacyclicly by `x`; it no longer treats a ring challenge as a coordinatewise integer vector.

## Open critical findings

### F-005 — Finite reference distributions are not exact paper distributions

`FiniteDiscreteGaussian` is a variable-time, finite-support inverse-CDF oracle. It reports an omitted-tail diagnostic but does not prove the exact `D_sigma` convention, smoothing condition, or `2^-100` statistical-distance target in Gao's Lemma 6.

### F-006 — No soundness reduction

The `(S,3)` relaxed-opening extractor, non-invertible challenge-difference handling, relaxed norm bounds, and `S <= 2` reduction have not been independently reproduced.

### F-007 — No SHVZK simulator

The code has honest algebraic transcripts only. It has no independently implemented simulator or transcript-distance experiment.

### F-008 — No concrete lattice estimate

Toy dimensions and moduli are not Module-SIS/Module-LWE security parameters. No 128-bit claim is permitted.

### F-009 — No transaction composition

Balance/range proofs, integer conservation, authorization, state/replay binding, and balance-recovery encryption remain separate work.

## Verdict

The lab now supports reproducible, self-verified synthetic Protocol 1-shaped experiments. It is not a secure proof system, wallet, ledger, consensus component, or production cryptographic implementation.