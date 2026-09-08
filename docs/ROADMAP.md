# PQ-CT Roadmap

## P0 — Reference arithmetic

- [x] Create an isolated research repository.
- [x] Define a small ring `Z_q[x]/(x^n+1)` reference model.
- [x] Implement canonical coefficient reduction.
- [x] Implement matrix-vector multiplication.
- [x] Implement additive commitments and openings.
- [x] Test homomorphic addition.
- [x] Test malformed input rejection.
- [x] Domain-separate transcript hashing.

## P1 — Security specification

- [x] Survey published lattice confidential-transaction candidates.
- [x] Select Gao et al. 2021/1674 as the first proof candidate to extract; keep LACT+ as the scalability comparison.
- [x] Freeze the first account-mode public/private statement boundary.
- [x] Extract the candidate’s core linear-equation relation and verification boundary from the paper.
- [x] Compare paper equations against the authors’ public toy implementation.
- [x] Record implementation blockers: missing norm/rejection checks, MD5 challenge, wall-clock randomness, restricted balance shape, and dependency bug.
- [x] Resolve the core PDF-level notation for the linear-equation/cycle-masking component.
- [x] State the exact remaining dependency boundary: commitment, binary proof, rejection sampler, and parameter proof are not yet implemented.
- [x] State hiding and binding games.
- [x] State exact HMC reference ring boundary; production Module-LWE/SIS parameters remain open.
- [x] Separate commitment functionality from encryption; HMC is commitment-only.
- [ ] Select and specify the separate balance-recovery encryption layer.
- [x] Define experiment matrix generation and candidate parameter report.
- [x] Complete internal independent-eyes review; record blockers and launch boundary.
- [ ] Define message, nonce, and address binding.
- [ ] Define overflow and balance-range policy.

## P2 — Proof system

- [ ] Evaluate published lattice range-proof constructions.
- [ ] Evaluate published multiplicative-relation proofs.
- [ ] Select a proof system only after proof-size and verifier-cost measurements.
- [ ] Bind account, asset, epoch, previous state, next state, and transaction ID.
- [ ] Add negative, overflow, replay, and cross-context rejection tests.

## P3 — Engineering

- [ ] Add independent slow reference implementation.
- [ ] Add optimized implementation and differential tests.
- [ ] Add serialization test vectors.
- [ ] Add fuzzing for every parser and verifier boundary.
- [ ] Measure proof size, proving time, verification time, RAM, and bandwidth.
- [ ] Add constant-time and side-channel review for secret operations.

## P4 — Shadow ledger

- [ ] Build a non-consensus shadow ledger.
- [ ] Replay synthetic transfers and known-value conservation cases.
- [ ] Compare EC and PQ representations without claiming equivalence.
- [ ] Run adversarial mutation campaigns.
- [ ] Obtain independent cryptographic review.

## P5 — Migration decision

- [ ] Publish a security document and limitations.
- [ ] Decide whether the scheme is suitable for a new account class.
- [ ] Specify migration and recovery semantics.
- [ ] Specify how legacy EC balances are treated.
- [ ] No hard-fork proposal before review approval.
