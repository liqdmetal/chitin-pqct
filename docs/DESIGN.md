# Design Notes — v0.1

## Scope

This document describes the first arithmetic reference model only. It is not a secure cryptosystem, range-proof implementation, encrypted-balance implementation, or consensus proposal.

## Current reference model

The package models a deliberately small negacyclic ring and an additive commitment-shaped relation:

```text
R = Z_q[x] / (x^n + 1)
C = A · r + g · m
```

The implementation is intended to test canonical encoding, dimensions, ring multiplication, additive composition, and opening verification.

## Literature-derived next layer

The first published proof candidate is Gao et al., IACR ePrint 2021/1674. Its balance component commits to the bits of bounded amounts and proves a weighted linear relation:

```text
B_i = Com_ck(bits(amount_i), randomness_i)
Σ_i ω_i · amount_i = 0
```

The bitwise relation is represented as:

```text
c_j = Σ_i ω_i · bit(amount_i, j)
Σ_j 2^j · c_j = 0
```

The candidate uses a lattice Sigma-protocol with challenge responses, norm bounds, rejection sampling, and cycle masking to avoid modular-wraparound ambiguity. Those components have not been implemented here.

## Account-mode target

For a DERO-style confidential account transition, the intended relation is:

```text
old_balance + credits - new_balance - debits - fee = 0
```

The terms must be bound to versioned account-state commitments and a domain-separated transaction transcript. The account mode does not initially include ring anonymity or a ring-signature protocol.

## Separation of roles

- The commitment hides/binds an amount representation.
- An encryption layer lets the authorized account owner recover state.
- A zero-knowledge proof establishes range and conservation.
- ML-DSA or a non-strippable hybrid signature authorizes the transition.
- Ledger state and nonce checks prevent replay and enforce ordering.

No current module combines these roles.

## Safety boundary

Do not use the current model for money, private keys, wallets, production cryptography, or consensus. Do not infer security from passing arithmetic tests. The complete published construction, parameters, distributions, proof transcript, and independent review remain required.
