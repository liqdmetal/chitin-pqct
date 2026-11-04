# Chitin — PQ-CT Research Lab

**Chitin** is the working name for this construction: chitin is the polymer
mycelial cell walls are made of — the rigid structure that makes the organism
hard to break. This is a project name, not a cryptographic security claim.

## Lineage

This repository is the **confidential-transactions research track** of the
Chitin family (lattice-based commitments). The separate **proof-of-work
track** (bounded-weight syndrome decoding, golden vectors, attack audits)
lives in [`pq-mining`](https://github.com/liqdmetal/pq-mining) and has a
research integration in [Noumenon](https://github.com/liqdmetal/Noumenon). This repository
remains a separate PQ-CT research lab; it is not integrated as live chain
confidentiality.

Post-quantum confidential-transaction research for a possible future account
mode; this repository has no DERO or live-chain integration.

**Status: research prototype only.** Nothing here is consensus-safe, production cryptography, or a claim of absolute quantum-proofness. Several real attacks were found and fixed during development (see docs/HARD_BLOCKER_PROGRESS.md); the soundness, SHVZK and Fiat–Shamir *proofs* are still absent, and no certified bit-security level exists.

## Current implementation

This repository establishes a clean reference model for a module-lattice-style additive commitment:

```text
C = A*r + g*m  (mod q)  in R_q^k
R_q = Z_q[x] / (x^n + 1)
```

It currently provides:

- explicit toy parameters for reproducible tests;
- canonical ring arithmetic and serialization;
- commitment opening verification;
- homomorphic addition of commitments/openings;
- transcript hashing with domain separation;
- explicit rejection of malformed dimensions and non-canonical values.

It does **not** provide:

- a secure parameter set;
- a range-proof construction with established soundness;
- a balance-conservation proof with established security;
- a secure encryption scheme;
- a wallet format;
- a consensus implementation;
- a claim that the construction is binding, hiding, or post-quantum secure.

The repository also contains experimental V2 proof and transaction-boundary
work: public-only proof codecs, verifier policy, note/proof commitment links,
authorization signatures, and atomic single-process simulator transitions.
These are implementation experiments, not completed cryptographic proofs or
production transaction functionality. Soundness, SHVZK, Fiat–Shamir security,
secure parameters, and independent review remain unresolved.

## Why this is separate from derohe

The current DERO balance representation is elliptic-curve based. In the checked source:

- `cryptography/crypto/algebra_elgamal.go:34-49` defines the EC ElGamal structure and commitment construction;
- `cryptography/crypto/algebra_elgamal.go:69-84` implements additive and plaintext operations;
- `cryptography/crypto/algebra_elgamal.go:87-112` serializes a balance as two compressed EC points;
- `cryptography/crypto/proof_verify.go:98+` verifies the existing EC proof system.

The PQ-CT work must therefore begin as an independent reference implementation. It must not be wired into consensus until the construction, proof system, parameters, implementation, and external review are complete.

## Run the tests

The current in-memory transaction boundary has a complete public-only V2
codec, node-pinned verifier policy, note/proof commitment linkage and atomic
simulator transitions. See [Transaction boundaries V2](docs/TRANSACTION_BOUNDARIES_V2.md)
for the exact scope and breaking transcript change. Private experiment results
still contain witnesses and must never be sent or logged as public proofs.
The composed proof algorithms remain unproven; these implementation checks do
not establish soundness, privacy or a secure parameter set.

From Git Bash:

```bash
cd <repo>
python -m unittest discover -s tests -v
```

## Work sequence

1. Reference commitment arithmetic — **started and tested**.
2. Formal statement of hiding/binding assumptions and security games.
3. Range proof candidate study; no custom proof accepted by default.
4. Balance-conservation proof design.
5. Parameter and performance study.
6. Differential/fuzz testing.
7. Independent cryptographic review.
8. Only then: shadow-ledger integration and migration design.

See `docs/THREAT_MODEL.md`, `docs/ROADMAP.md`, and `FAQ.md`.
