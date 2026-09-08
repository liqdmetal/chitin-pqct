# Real testnet scope: pq-ct-research + Obscura

STATUS: planning document only. No code, no deployment, no consensus
changes. This exists to make the distance from "toy research lab" to
"real experimental testnet" concrete and honest, per the user's explicit
request to keep pursuing testnet+Obscura goals eventually.

## Hard rule this doc does not change

No production, testnet, or mainnet deployment is authorized until:
(a) every item in Section 1 below is closed, AND (b) the user explicitly
authorizes deployment as a separate, explicit act (this doc's existence
is not that authorization). Writing a scope document is planning, not
a green light.

## 1. What must be true of the crypto before ANY testnet code exists

Pulled directly from `docs/HARD_BLOCKER_PROGRESS.md`'s "Still open" list.
None of these are close:

1. Complete equations (38)-(45) binary-witness soundness (in progress
   as of this session; see docs/BINARY_RELATION.md).
2. Full HMC computational-binding reduction (general case, not just
   the collision-to-SIS step already done).
3. SHVZK simulator rejection gate (simulator currently has NO Rej()
   stage at all -- it satisfies verifier equations by construction,
   which is not the same as proving indistinguishability).
4. Fiat-Shamir security proof in the (quantum) random-oracle model
   (not attempted; this is a real research-paper-scale task).
5. Verified (not self-built) Module-SIS/Module-LWE hardness estimate
   via the real `lattice-estimator` tool (needs fpylll/Sage, not
   installable in this environment).
6. Balance/range/conservation composition (amount ciphertext, integer
   conservation across inputs/outputs, authorization, replay/state
   binding) -- currently ZERO of this exists; Protocol 1 alone proves
   binary/range facts, not a working confidential-transaction scheme.
7. Independent second implementation (Rust/C/Sage) of the prover,
   verifier, and extractor, cross-checked against the Python reference.
8. External cryptanalysis: at least one qualified lattice/ZK reviewer
   who did not write this code, per the resource plan in
   docs/HARD_BLOCKER_RESOURCE_PLAN.md ($65k-$192k estimate,
   independent implementation + lattice/ZK/constant-time review).

None of items 1-8 are done. Item 1 is furthest along (this session).

## 2. What "experimental testnet" would actually require (once Sec.1 closes)

This is infrastructure work, completely separate from the crypto work
above, and separate again from whether the crypto is ready:

### 2a. Concrete parameters (not toy)

- A real Module-SIS/Module-LWE parameter set at a stated (e.g. 128-bit
  classical / lower quantum) security level, from the verified estimator,
  not the toy `ToyParameters(n=8,q=12289)` fixtures used throughout this
  repo's tests.
- Independent M-SIS/M-LWE review confirming the parameter choice
  actually delivers the claimed security level for the FULL protocol
  (binary + range + linear-equation + ring signature composition),
  not just the toy binary proof alone.

### 2b. Node/consensus integration (net-new work)

- A running DERO-compatible (or standalone) node with a NEW transaction
  type carrying the PQ-CT proof, separate from existing DERO tx types
  (per the standing rule: never modify existing DERO consensus code).
- Consensus rules for the new tx type: proof verification cost, fee
  accounting for the (much larger) PQ proof size, block size/timing
  impact of larger proofs and slower Decimal-based verification.
- A wallet/CLI that can construct, sign, and broadcast the new tx type.
- Genesis/bootstrap for an isolated test network (own genesis block,
  own seed nodes, clearly NOT connected to DERO mainnet or any
  production network).

### 2c. Obscura-specific integration

Per memory: Obscura's confidential DVM intrinsics (verify_sig,
pedersen_commit, verify_commit, ec_add, hash_to_point, asset_balance,
strictDecodeG1) live in the PRIVATE fork
`liqdmetal/derohe-intrinsics` (feat/obscura-intrinsics branch). That
codebase is CLASSICAL (elliptic-curve, pre-quantum) confidential
settlement, entirely separate from this repo's lattice-based PQ work.

Combining them for a testnet would require:

- A decision on scope: does the PQ scheme REPLACE Obscura's classical
  primitives, run ALONGSIDE as a separate tx type, or is this a hybrid
  transition (Ed25519+ML-DSA style, non-strippable) -- this decision
  has NOT been made per current memory.
- Independent security review of how the lattice-based confidential
  amount commitments interact with Obscura's elliptic-curve commitments
  if both must coexist on one chain (e.g. cross-rail balance proofs,
  atomic swap correctness).
- Explicit re-affirmation from the user that the private
  `derohe-intrinsics` fork is the intended integration point, since
  that decision belongs to the user, not this agent.

## 3. Honest bottom line

Section 1 (crypto correctness) is months of work at minimum, most of it
requiring skills (formal lattice cryptography, ZK soundness proofs) beyond
what can be safely closed by an AI agent alone, however careful. Section 2
(node/wallet/network plumbing) is comparatively mechanical once Section 1
is real, but should not START until Section 1 is real -- building a
testnet around unfinished crypto just gives the unfinished crypto a
misleadingly production-looking wrapper. Keep plugging on Section 1
first.