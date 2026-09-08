# University-Level Study and Audit Plan

This plan is for research hardening before approaching a university cryptography group. It does not claim that internal testing substitutes for peer review.

## Phase 0 — Reproducible research record

- Pin paper versions, source URLs, repository commit IDs, and local toolchain versions.
- Maintain a notation glossary mapping every paper symbol to code types and serialization.
- Keep the DERO repository untouched.
- Record every parameter as either paper-reproduced, toy, or proposed.
- Make all test runs reproducible from a clean checkout.

## Phase 1 — Independent mathematics

Two people or two independently written implementations should derive:

- ring and matrix dimensions;
- commitment equations;
- bit decomposition and weighted relation;
- cycle-masking identity;
- challenge derivation;
- response equations;
- norm bounds and rejection conditions;
- completeness error;
- extraction/special-soundness argument;
- zero-knowledge simulator behavior.

Disagreements become tracked issues, not patched by intuition.

## Phase 2 — Reference implementation

Build a deliberately slow implementation with:

- arbitrary-precision integer checks at every boundary;
- canonical serialization;
- injected CSPRNG interface;
- deterministic test vectors using fixed randomness only;
- transcript hash domain separation and length framing;
- explicit rejection of malformed dimensions, noncanonical coefficients, bad norms, bad challenges, and overflow;
- no optimized NTT until the slow model is stable.

## Phase 3 — Differential and adversarial testing

Compare the slow reference against an optimized implementation across generated cases:

- honest proofs across supported dimensions;
- wrong amount, wrong opening, wrong commitment;
- altered first message, challenge, or response;
- non-binary bit vectors;
- modular-wraparound attempts;
- norm-bound boundary values;
- rejection-sampling acceptance and failure cases;
- serialization mutations and truncation;
- transcript field reordering and length-prefix ambiguity;
- replay under a different account, asset, epoch, nonce, or chain domain;
- malformed ring/matrix dimensions;
- randomness reuse detection in test instrumentation.

## Phase 4 — Property and model testing

Use property-based tests and, where tractable:

- bounded exhaustive search for tiny rings;
- mutation testing against the verifier;
- SMT-assisted checking of the integer-vs-modular relation;
- symbolic checks of transcript binding;
- fuzzing of every parser and verifier boundary;
- performance measurements separated into proving, verification, memory, and wire size.

A passing test is evidence of exercised behavior, not a proof of security.

## Phase 5 — Security argument

Write a formal security document covering:

- hiding game;
- binding game;
- knowledge soundness / special soundness;
- Fiat–Shamir model and quantum-query limitations if claimed;
- zero-knowledge definition and simulator;
- Approx-SIS / Module-SIS / Module-LWE assumptions as applicable;
- parameter estimator methodology;
- concrete security margin and failure probability;
- multi-instance and multi-user considerations;
- side-channel and implementation assumptions.

Do not use “post-quantum” without naming the assumption and parameter estimate.

## Phase 6 — Internal cryptographic review

Produce a review package containing:

- one-page construction summary;
- threat model;
- notation and protocol specification;
- implementation and test-vector repository;
- independent implementation comparison;
- adversarial test report;
- known limitations and unresolved questions;
- reproducibility instructions;
- proposed university questions.

Internal review should seek reasons the construction fails, not confirmation that it works.

## Phase 7 — University engagement

Approach a lattice cryptography, zero-knowledge, or blockchain-security group with a narrow request:

1. verify the extracted equations;
2. challenge the security reduction and parameter selection;
3. inspect the account-mode adaptation;
4. review implementation boundaries and test evidence;
5. identify a publishable contribution, if any.

Ask for criticism before asking for endorsement. Offer the complete artifact and reproducible environment, not a marketing claim.

## Exit gates

No production or consensus integration unless all are true:

- exact published construction reproduced;
- independent implementation agrees on vectors;
- adversarial campaigns pass with no unexplained failures;
- security assumptions and concrete parameters are documented;
- implementation review is complete;
- independent cryptographers have reviewed the design;
- migration, recovery, and failure semantics are specified;
- residual weaknesses are accepted explicitly.
