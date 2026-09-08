# PQ-CT Threat Model

## Scope

This lab studies confidential account state and transaction proofs against a future quantum-capable attacker. It does not claim to solve wallet compromise, traffic analysis, denial of service, or quantum attacks on arbitrary future primitives.

## Assets

- account balance confidentiality;
- balance conservation and non-negativity;
- authorization to mutate an account;
- replay and double-spend resistance;
- canonical, deterministic consensus encoding.

## Adversaries

1. **Passive archival attacker:** records historical chain data and later obtains a cryptographically relevant quantum computer.
2. **Active classical attacker:** submits malformed commitments, proofs, encodings, replays, and boundary values.
3. **Active future quantum attacker:** runs quantum algorithms against the stated hardness assumptions and any remaining elliptic-curve component.
4. **Malicious prover:** knows arbitrary values and attempts to create an accepted invalid balance transition.
5. **Implementation attacker:** exploits parser disagreement, non-canonical encodings, integer overflow, timing, or memory-safety defects.

## Non-goals

- No claim that a toy commitment is secure.
- No claim that ML-KEM or ML-DSA automatically protects homomorphic balance arithmetic.
- No consensus change in this repository.
- No replacement of the existing DERO EC balance format.
- No custom range-proof design accepted without a written reduction or external cryptographic review.

## Required security properties

### Confidentiality
A public observer should not recover the committed amount from a valid commitment under the stated lattice assumptions, except through intentional leakage such as amount bounds, transaction size, or metadata.

### Binding
A malicious prover must not produce one commitment with two distinct valid openings, except with negligible probability under the declared assumption and parameters.

### Homomorphic correctness
For valid openings `(m1, r1)` and `(m2, r2)`, adding commitments must equal a commitment to `m1 + m2` with opening `r1 + r2`, subject to the ring modulus and explicit overflow policy.

### Proof soundness
A verifier must accept only transitions satisfying authorization, conservation, range, and replay constraints. A passing unit test is not a soundness proof.

### Canonical consensus behavior
Every accepted byte string must have one interpretation. Reject non-canonical coefficients, dimensions, lengths, and duplicate fields.

## Quantum boundary

Hashing and symmetric encryption are separate from the lattice commitment. ML-KEM protects key establishment; ML-DSA protects signatures. Neither one proves that a lattice commitment or its zero-knowledge proof is secure. The final design must identify the exact hardness assumption for each primitive and every classical or elliptic-curve dependency must be labeled as non-PQ.
