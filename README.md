# Chitin — PQ-CT Research Lab

**Chitin** is the working name for this construction: chitin is the polymer
mycelial cell walls are made of — the rigid structure that makes the organism
hard to break. It sits in the Spore → Mycelium → Sap → Physarum → Rhizome
line as that organism's actual armor. Name verified clear of existing
crypto/PQ projects (only the biopolymer uses it).

Post-quantum *resistant* confidential-account transaction research for a future DERO-compatible account mode.

**Status: research prototype only.** Nothing here is consensus-safe, production cryptography, or a claim of absolute quantum-proofness. Several real attacks were found and fixed during development (see docs/HARD_BLOCKER_PROGRESS.md); the soundness, SHVZK and Fiat–Shamir *proofs* are still absent, and no certified bit-security level exists.

## First milestone

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
- a range proof;
- a balance-conservation proof;
- a secure encryption scheme;
- a wallet format;
- a consensus implementation;
- a claim that the construction is binding, hiding, or post-quantum secure.

## Why this is separate from derohe

The current DERO balance representation is elliptic-curve based. In the checked source:

- `cryptography/crypto/algebra_elgamal.go:34-49` defines the EC ElGamal structure and commitment construction;
- `cryptography/crypto/algebra_elgamal.go:69-84` implements additive and plaintext operations;
- `cryptography/crypto/algebra_elgamal.go:87-112` serializes a balance as two compressed EC points;
- `cryptography/crypto/proof_verify.go:98+` verifies the existing EC proof system.

The PQ-CT work must therefore begin as an independent reference implementation. It must not be wired into consensus until the construction, proof system, parameters, implementation, and external review are complete.

## Run the tests

From Git Bash:

```bash
cd /c/Users/officeone/pq-ct-research
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

See `docs/THREAT_MODEL.md` and `docs/ROADMAP.md`.
