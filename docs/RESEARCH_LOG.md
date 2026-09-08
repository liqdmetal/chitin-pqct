# PQ-CT Research Log

## 2026-09-07 — Candidate selection

### Finding
The toy additive ring commitment is useful as an arithmetic scaffold only. It must not be described as a secure lattice commitment: it has no sampled security parameters, bounded-noise/security distribution, proof system, or reduction-backed security claim.

### Literature checked

- **Gao et al., IACR ePrint 2021/1674**, revised publication information lists PKC 2025. The abstract describes an inner-product-based linear-equation satisfiability approach for balance proofs with a wide range, a linear-sum approach for ring signatures, and a logarithmic-size ring-signature direction. The paper reports reductions in proof size and proving/verification time against MatRiCT and MatRiCT+ for its own prototype.
- **LACT+ (Alupotha, Boyen, McKague, 2023)** describes a lattice-based aggregable confidential-transaction construction, including carry proofs and aggregation. The article reports a 5.7 KB confidential monetary value in its model and emphasizes logarithmic-size complexity for many-input/many-output aggregation.

### Decision
Use Gao et al. 2021/1674 as the first proof-construction to extract and reproduce. Keep LACT+ as the scalability and aggregation comparison. Do not claim either is a drop-in DERO account-mode design.

### Account-mode boundary
The first DERO-compatible relation is conservation plus range for a committed old balance, new balance, credits, debits, and fee. Ring anonymity is explicitly deferred. Authorization is a separate ML-DSA/hybrid signature relation, not silently assumed to be supplied by the balance proof.

### Next executable step
Extract the exact candidate commitment and balance-proof equations from the paper into a formal notation document, then implement only a verifier/reference transcript for those equations. No secure parameter guessing and no consensus wiring.
