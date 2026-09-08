# Parameterization and Independent-Eyes Review

**Status:** experiment candidates only; no production security claim.

## Parameter candidates

| Candidate | Ring `n` | Modulus `q` | `m` | `d` | Amount bits | Inputs/outputs | Status |
|---|---:|---:|---:|---:|---:|---:|---|
| toy-ntt-32 | 32 | 12,289 | 8 | 32 | 8 | 2 / 2 | research-only |
| toy-ntt-64 | 64 | 786,433 | 16 | 64 | 16 | 4 / 4 | research-only |

Both satisfy `q ≡ 1 (mod 2n)`, which is required for the negacyclic NTT candidate. Neither has a concrete Module-SIS/LWE security estimate.

## Independent-eyes review

### Finding P-001 — No security claim

The candidates are explicitly labeled `UNASSESSED_RESEARCH_CANDIDATE`. They are useful for arithmetic experiments and transcript profiling only.

### Finding P-002 — The current challenge is not the paper challenge

The harness uses a bounded scalar challenge to avoid toy-ring wraparound. Gao’s construction uses a sampled ring-valued challenge. This remains a hard blocker before claiming paper-level reproduction.

### Finding P-003 — The current sampler is not `D1/D2/D3`

The code has the rejection acceptance equation but not the exact discrete distributions, smoothing parameters, statistical distance, or acceptance calibration.

### Finding P-004 — The matrices are not security-generated

`G_r` and `G_m` are supplied toy matrices. A production candidate needs specified public-matrix generation, distribution, seed expansion, canonical serialization, and parameter-estimator evidence.

### Finding P-005 — Security proof is not inherited automatically

The transcript shape and passing tests do not establish hiding, binding, special soundness, knowledge soundness, zero knowledge, or post-quantum security for this adaptation.

## Launch protocol

1. Run the candidate report and archive the JSON output.
2. Run the complete test suite.
3. Run bounded exhaustive relation checks for tiny rings.
4. Run mutation tests against commitments, challenges, bounds, and serialization.
5. Record failures as issues; do not patch tests to make a candidate green without a written rationale.
6. Do not connect this package to DERO, wallets, real balances, or production keys.
7. Send the resulting review bundle to a university cryptography group only as a research artifact requesting criticism.
