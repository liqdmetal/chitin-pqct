# Reference Implementation Audit — Gao / RingCT_Implementation

**Repository:** https://github.com/GoldSaintEagle/RingCT_Implementation
**Local checkout:** the vendored `RingCT_Implementation` tree (see `vendor/`).
**Purpose:** understand the paper-to-code boundary. This checkout is vendor research material, not trusted cryptographic code and not part of the PQ-CT package API.

## Verification performed

- Cloned the public repository at the current default branch.
- Confirmed the repository README explicitly labels the code a **toy implementation** and says not to use it in production.
- Confirmed the checkout is clean and tracks `origin/master`.
- Read the balance-proof and linear-equation implementation paths.

## Findings

### R-001 — Production cryptography is explicitly out of scope

The repository README labels the implementation as toy code. It is suitable for understanding interfaces and locating paper equations, not for importing into a wallet, ledger, or consensus implementation.

### R-002 — The implementation does not implement the complete supported relation

`Matrict.go` documents that the balance proof only supports one input and at most two outputs because corrector-value range proofs are embedded only in that restricted case. `BalanceProof` returns an error for larger shapes.

This does not meet the account-mode target by itself.

### R-003 — Rejection sampling and norm checks are incomplete

`Matrict.go` marks the bound checks as TODO in both proving and verification paths. The code comment in `BalanceProofII` says rejection sampling is ignored. `Matric+_plus.go` similarly marks bound verification as TODO.

A proof implementation without these checks cannot be treated as a sound lattice Sigma protocol.

### R-004 — Hash challenge construction is unsuitable for production

`Basic.go` implements the challenge using MD5, truncates to eight bytes for a `math/rand` seed, and samples coefficients with the non-cryptographic global PRNG. The source comment itself calls the mapping high-collision.

This is unacceptable for Fiat–Shamir challenges or consensus cryptography. We will use a canonical, length-delimited, domain-separated cryptographic transcript hash in the research implementation.

### R-005 — Secret randomness uses wall-clock seeding

`Basic.go` uses `time.Now().UnixNano()` to seed commitment randomness. That is not a cryptographic randomness source and creates predictability/collision concerns.

We will use an explicit CSPRNG interface and make randomness injectable for deterministic test vectors only.

### R-006 — Upstream dependency has a documented arithmetic bug

The repository README documents a `MulPoly` bug in the LAGO dependency involving repeated NTT operations when multiplying the same input. The repository adds a compatibility flag/workaround rather than providing a formally verified arithmetic layer.

No dependency code is being copied into the PQ-CT lab. Any future ring arithmetic must be differentially tested against an independent slow implementation.

### R-007 — Current verifier mostly checks transcript consistency, not a complete security boundary

The linear-equation verifier reconstructs commitments and recomputes the challenge, but the source contains explicit TODOs for norm bounds. Transcript consistency is necessary and insufficient for soundness.

### R-008 — The implementation contains CGo scaffolding and no isolated module manifest

The code imports `C` in core files and relies on the external LAGO package. It is not a clean embeddable library with a pinned, independently audited dependency graph.

## Consequence for PQ-CT

We will **not** fork or import this code into the research package. We use it only to:

1. compare paper notation to code;
2. identify all protocol components and dependencies;
3. build independent test vectors;
4. reproduce positive and negative cases;
5. document defects and missing security checks.

The next implementation milestone is a clean, standalone **reference-only** verifier/prover for a reduced linear relation with:

- PDF-reconciled cycle masking and omitted-coordinate reconstruction;
- explicit toy parameters;
- a cryptographic transcript hash;
- deterministic injected randomness for tests;
- exact norm/encoding checks;
- no production-security claims;
- independent arithmetic cross-checks.

It must not be called a Gao-compatible implementation until the PDF notation, commitment dimensions, rejection distributions, and all binary-proof dependencies are reconciled exactly.
