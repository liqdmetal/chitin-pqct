# Independent-Eyes Review — Parameterized PQ-CT Experiment

**Review status:** internal pre-university review, not an external audit.

## Scope reviewed

- `pqct/parameterization.py`
- `pqct/parameters.py`
- `pqct/matrix_generation.py`
- `pqct/challenge.py`
- `pqct/gaussian.py`
- `pqct/independent_oracle.py`
- `pqct/hmc.py`
- `pqct/hmc_transcript.py`
- `pqct/binary_hmc.py`
- `pqct/rejection_sampling.py`
- `docs/FORMAL_SPEC.md`
- Gao et al. IACR 2021/1674 PDF extraction

## Findings

### IR-001 — Candidate parameters are not security parameters

**Severity:** blocking for deployment; accepted for experiment.

The candidate profiles are useful for arithmetic, serialization, and performance experiments. They do not have a Module-SIS/LWE estimate, concrete failure probability, or verified relation to the paper's claimed target.

**Disposition:** retain `UNASSESSED_RESEARCH_CANDIDATE`; no wallet or consensus use.

### IR-002 — Public matrix generation is reproducible, not secure

The experiment generates `G_r` and `G_m` from a domain-separated SHAKE256 seed with rejection-mapped uniform coefficients. This fixes reproducibility and vector publication, but does not establish matrix quality, trapdoor absence, or security.

**Disposition:** matrix generation is closed for the experiment harness; security generation remains an external-review item.

### IR-003 — Sparse challenge set shape is enforced, but Fiat–Shamir is not paper-complete

`pqct.challenge` enforces degree `n-1`, exactly `w` nonzero coefficients, and every nonzero coefficient of absolute value exactly `p`. The deterministic sampler is still not the final Fiat–Shamir transform: transcript canonicalization, challenge rejection/mapping, ring-valued integration into every proof equation, and security analysis remain open.

**Disposition:** challenge-set shape is closed for vector experiments; paper-level Fiat–Shamir reproduction remains open.

### IR-004 — Exact `D₁/D₂/D₃/S_B` samplers remain open

The rejection acceptance equation and a finite-support Gaussian-shaped reference distribution are exercised, but the paper's exact discrete distributions, smoothing parameters, majorants, statistical distance, and acceptance rate are not established.

**Disposition:** next blocker; no security claim.

### IR-005 — Binary transcript is shape-compatible, not proof-complete

The prover harness now rejects a mismatched public bit commitment at its API boundary by checking every `B_i = Com(b_i; r_b,i)` against the supplied witness. This closes the unchecked-witness path in the local harness and has regression coverage.

That check is not a zero-knowledge proof: the verifier cannot establish the relation from a proof alone because the full non-homomorphic Protocol 1 transcript, exact rejection sampling, and extraction argument are not implemented. `E/F/G` objects, response equations, and mutation checks exist; the full relaxed-opening extraction argument and all paper norm distributions remain unverified.

### IR-006 — No balance-recovery encryption

HMC hides a message under assumptions; it does not give the account owner a practical decryptable balance. Recovery encryption, key rotation, nonce/state semantics, and authorization remain outside this experiment.

### IR-007 — No production parameter estimate

The paper-reported profile is recorded as historical source data only. The local profiles are deliberately toy candidates. No estimator output has been used to label any profile 128-bit PQ.

### IR-008 — Independent oracle agrees only on arithmetic, not on security

`pqct.independent_oracle` implements separate tuple-based negacyclic multiplication, matrix commitment arithmetic, and bounded exhaustive relation checks. It agrees with the main arithmetic path on the tested domain. This is useful differential evidence, not a proof of the transcript or its security reduction.

## Launch decision

**Approved:** isolated, no-consensus, no-money research experiment with synthetic values only.

**Not approved:** production use, real wallet keys, real balances, DERO integration, consensus changes, or “128-bit PQ” marketing.

## Required evidence before university submission

- pinned source/PDF hashes;
- clean-checkout test command and output;
- parameter report;
- seeded matrix, sparse-challenge, and sampler vectors;
- exact sampler specification and empirical report;
- independent second full transcript implementation;
- mutation and bounded-exhaustive reports;
- unresolved-risk register;
- independently checked security argument.
