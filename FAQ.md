# FAQ — Chitin (PQ-CT research track)

**Is this usable cryptography?**
No. Research prototype only. It establishes a reference model for a
module-lattice-style additive commitment (`C = A·r + g·m (mod q)` in
`R_q^k`): canonical ring arithmetic, commitment opening, homomorphic
addition, domain-separated transcript hashing, malformed-input rejection.
It provides **no** secure parameter set, range proof, balance-conservation
proof, encryption scheme, or wallet format — and makes no binding/hiding/
post-quantum claim.

**Is it post-quantum secure?**
Unproven. The soundness, SHVZK and Fiat–Shamir proofs are absent and no
certified bit-security level exists. Several real attacks were found and
fixed during development (see `docs/HARD_BLOCKER_PROGRESS.md`); that is
research progress, not security.

**Why is this separate from derohe?**
Current DERO balances are elliptic-curve ElGamal commitments. This is an
independent lattice-based reference implementation for a *future*
DERO-compatible account mode. It must not be wired into consensus until
construction, proof system, parameters, implementation, and external
review are complete.

**How does this relate to Chitin-PQ proof of work?**
`pq-mining` (repo `liqdmetal/pq-mining`) is the Chitin-PQ proof-of-work
track (bounded-weight syndrome decoding) with a research integration in
Noumenon. This repository is the separate confidential-transactions research
track; it is not live chain confidentiality. Its V2 codecs, verifier policy,
signature checks and atomic simulator exercise interfaces only and do not
establish soundness, privacy or production security.

**What's the next milestone?**
Formal statement of hiding/binding assumptions and security games, then a
range-proof candidate study — no custom proof accepted by default. Full
work sequence in `docs/ROADMAP.md`.

**Can I reproduce the tests?**
Yes: `python -m unittest discover -s tests -v` from the repository root.
No secrets, network access, or special hardware required.
