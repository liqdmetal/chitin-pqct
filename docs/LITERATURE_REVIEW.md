# PQ-CT Literature Review — v0.1

## Decision

Do **not** invent a complete post-quantum confidential-transaction proof system from the toy scaffold. The first serious candidate family is a published lattice commitment plus Fiat–Shamir lattice proof system, with the account-model statement adapted to DERO.

The two primary candidates are:

1. **Gao et al., “Lattice-based Zero-knowledge Proofs for Blockchain Confidential Transactions,” IACR ePrint 2021/1674; revised publication information lists PKC 2025.**
2. **Alupotha, Boyen, McKague, “LACT+: Practical Post-Quantum Scalable Confidential Transactions,” Cryptography 7(2), 24 (2023).**

This is a research selection, not a security endorsement.

## Candidate comparison

| Candidate | Useful property | DERO fit | Main blocker |
|---|---|---|---|
| Gao et al. 2021/1674 | Inner-product balance proof; 64-bit-style range; avoids some corrector values; logarithmic-size linkable ring-signature direction | **Best first proof candidate** for balance/range research; account adaptation may remove ring machinery | Need exact algorithms, parameter tables, proof transcript, soundness model, and implementation verification |
| LACT+ 2023 | Confidential coins, carry proofs, aggregation, logarithmic complexity; reports 5.7 KB confidential monetary value in its model | Useful for scalability and aggregation ideas | Coin/aggregable transaction model is not a drop-in replacement for DERO’s encrypted account balance |
| MatRiCT / MatRiCT+ lineage | Established lattice RingCT design family | Relevant baseline and comparison point | Corrector values and proof cost; ring/coin model differs from DERO account state |
| STARK-style general ZK | Transparent and generally post-quantum assumptions when instantiated carefully | Could prove an account transition without a bespoke lattice CT proof | Proof size, prover cost, and amount hiding/commitment interface still need a concrete design |

## What we carry forward

### 1. Account model, not ring model

DERO’s current state is an encrypted account balance, not a Monero-style input ring. The initial PQ statement should therefore prove:

```text
new_state = old_state + credits - debits
0 <= every debit and credit < 2^B
authorization binds the account and transaction
```

A ring-signature component is **not** part of the first account-mode milestone. Adding ring anonymity merely because a paper supports it would increase attack surface and proof size without solving the immediate EC-balance problem.

### 2. Separate commitment, encryption, and proof roles

The literature uses closely related but distinct objects. The design must not conflate them:

- **Commitment:** public binding/hiding representation of an amount;
- **Encryption/ciphertext:** recipient or account owner recovery of the amount/state;
- **Proof:** zero-knowledge evidence of range, conservation, and authorization;
- **Signature:** authorization under a PQ identity key.

ML-KEM and ML-DSA do not replace the first three objects.

### 3. Published assumptions only

Every candidate must document whether it relies on Module-SIS, Module-LWE, ring-SIS, a random-oracle/Fiat–Shamir model, rejection sampling, or additional assumptions. “Lattice-based” alone is not a sufficient security statement.

## Required extraction before implementation

Before coding a candidate proof, extract and cite:

- exact commitment equation and message embedding;
- randomness distribution and norm bounds;
- challenge space and Fiat–Shamir transcript order;
- completeness equation;
- knowledge-soundness or special-soundness argument;
- zero-knowledge simulator or statistical/computational hiding argument;
- parameter set and claimed security level;
- rejection-sampling conditions and failure behavior;
- serialization format and canonical decoding rules;
- proof-size and verification-cost measurements;
- assumptions that remain classical or non-standard.

## Selection gate

A candidate is not selected for a shadow ledger until all of these pass:

- [ ] independent re-derivation of the verification equations;
- [ ] test vectors generated from a separate reference implementation;
- [ ] malformed transcript, challenge, norm, and encoding rejection tests;
- [ ] soundness-focused mutation tests;
- [ ] parameter reproduction from the paper, not guessed values;
- [ ] comparison against at least one alternative construction;
- [ ] external cryptographic review plan.

## Sources

- Gao et al., IACR ePrint 2021/1674: https://eprint.iacr.org/2021/1674
- Gao et al. paper PDF: https://www4.comp.polyu.edu.hk/~shanggao//publications/Lattice-based_Zero-knowledge_Proofs_for_Blockchain_Confidential_Transactions.pdf
- Alupotha, Boyen, McKague, LACT+: https://www.mdpi.com/2410-387X/7/2/24

The source papers report performance and security arguments for their own constructions. Those claims are not automatically transferable to a DERO account-mode adaptation.
