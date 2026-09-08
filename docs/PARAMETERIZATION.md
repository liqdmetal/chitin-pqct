# Parameterization and Independent Review — v0.1

## Paper profile recorded

The lab records the paper's reported evaluation profile separately from the executable toy harness:

```text
d = 64
w = 56
p = 8
q = 2^49 - 2^18 + 2^9 + 1
n = 29
m = 60
amount bits k = 64
outputs S = 1
```

The paper reports these settings as targeting 128-bit post-quantum security for its complete construction and small-output binary proofs. That statement is **not independently verified here** and must not be transferred to the toy code.

## Executable profile

The current Python harness uses small rings such as:

```text
n = 2 or 4
q = 12289 or 17
challenge bound <= 31
```

These profiles have **zero claimed security**. They exist for exhaustive reasoning, mutation tests, and transcript debugging.

## Conservative response accounting

For scalar toy testing:

```text
|x*w + d| <= challenge_bound*witness_bound + mask_bound
|d_j| <= 3*sample_bound
```

These bounds are bookkeeping checks only. They do not establish a valid Gao parameter set because the paper's proof uses ring-valued sparse challenges, module dimensions, discrete distributions, rejection sampling, and relaxed openings together.

## Review rules

1. No parameter profile is called production, secure, or PQ-secure without an external estimator and a proof-level review.
2. Paper-reported parameters are not silently copied into the toy implementation.
3. Every parameter has a provenance label: `paper-reported`, `toy`, or `proposed`.
4. Any proposed profile must include dimensions, distributions, norm bounds, challenge space, completeness error, soundness error, and estimator output.
5. A passing test is not a security estimate.
