# Experimental transaction boundary V2

This document describes the current in-memory implementation. It supersedes
the plumbing status and partial 477-byte payload example in TESTNET_SCOPE.md.
It does not close the cryptographic research gates in HARD_BLOCKER_PROGRESS.md.
There is no network, persistence, consensus, money, anonymity set, recipient
encryption or certified security level here.

## What enters the verifier

`ExperimentalNode.submit(payload: bytes)` accepts a complete bounded canonical
transaction. `validate(payload)` performs the same checks without changing
the mempool, registry, replay markers or block state. Callers cannot supply a
separate proof, statement, commitment key or verifier bounds to the node.

Each node pins a `VerifierConfig`: HMC key, Protocol 1 and 5 bounds, bit width,
transaction shape, input/output roles and explicit permission for proof-only
experiments. The profile hash binds all of these. A different shape requires
a different explicitly selected profile; this is intentionally a small
research harness rather than a general wallet/node protocol.

The Fiat-Shamir statement includes the profile hash and envelope's chain ID,
previous state, nonce, expiry and dimensions. Genesis identity commits to the
profile and genesis note IDs. Genesis amounts remain trusted allocations.

## Public versus private types

`TransactionProof` remains a PRIVATE experiment result, including plaintext
amounts, sampling masks, rejection diagnostics and witness-derived columns.
Its `public_proof()` method exports only `PublicTransactionProof`:

- bit width, signed input/output roles and shared commitments;
- Protocol 1 public commitments and responses for each amount;
- Protocol 5 public commitment and responses.

The canonical encoder rejects private experiment result types. Verification
uses `verify_public_transaction` and never needs private traces. The older
`verify_transaction` function is a compatibility adapter for in-process
research tests; it is not the node's wire boundary. Exporting or logging private
experiment results would still reveal witnesses, and is not a supported API.

## Full transaction encoding

All unsigned integers are big-endian. The V2 transaction contains, in order:

1. `CHITIN-PUBLIC-TX-EXPERIMENTAL-V2` magic and a 32-byte profile hash.
2. Envelope: chain-ID length (u16), bytes, state root (32 bytes), nonce and expiry (u64 each).
3. Explicit proof-only mode (u8), bit width and amount count (u16 each), roles (one 0/1 byte each).
4. One commitment vector per amount; one complete public Protocol 1 proof per amount.
5. Public Protocol 5 commitment, response tail and opening response.
6. Input count (u16), 32-byte spent-note IDs; output count (u16), full output notes.
7. Signature count (u16), one fixed-size ML-DSA-65 signature per input.

Vectors have u32 element counts checked against the pinned profile before
allocation. Ring coefficients use the modulus-derived byte width and reject
values outside `[0,q)`. Every output includes length-prefixed commitment bytes,
the owner key, creation context and output index. Its creation context is the
profile/envelope statement; its index is the output's position. The decoder
rejects alternate counts, unknown profiles, truncation, trailing bytes and
encodings that do not round-trip byte-for-byte. Payloads are limited to 2 MiB;
profiles have at most 32 amounts, ring degree 4096 and modulus width 512 bits.
These are implementation resource limits, not approved cryptographic parameters.

The txid hashes these complete bytes. ML-DSA authorization covers a separate
domain and the complete unsigned encoding with an empty signature list. Thus
every proof byte, note, profile and envelope field is signed. Distinct valid
randomized signatures may produce distinct txids; spent-note tracking prevents
using that fact to spend the same input twice.

## Commitment linkage and atomicity

For each positive role, the node requires the proved commitment to equal the
known unspent input note's canonical commitment. For each negative role, it
requires equality with the newly created output note. Counts and roles come
from the profile. Ownership signatures are necessary in addition to these
equality checks; a valid balanced proof alone cannot authorize arbitrary notes.

Admission reserves transitions in the mempool but does not consume committed
notes or replay markers. Pending double spends are checked against a temporary
overlay. Eviction releases reservations, including later dependent entries.
Sealing revalidates the complete block at its new height in a temporary registry
and publishes registry, replay markers and block state together under the node
lock. Any rejection leaves all committed state unchanged. Replay uses canonical
txids and spent notes, not a global nonce shared between unrelated senders.

This atomicity is for the single-process simulator only. Durable database
transactions, crash recovery and distributed ordering remain unimplemented.

## Breaking transcript change

Ring and HMC key transcript encodings are now explicitly versioned V2 and share
bounded length-prefixed modulus encoding with the wire codec. Moduli wider than
32 bits no longer overflow the Fiat-Shamir transcript. Old V1 proof artifacts
must be regenerated; they are not reinterpreted as V2 proofs. Supporting a wide
modulus says nothing about its security or whether the full parameter set is valid.

## Verification

Run `python -m unittest discover -s tests -q`, then `python tools/stack_check.py`
in an environment with the project's test dependencies. `tools/run_testnet.py`
now transmits complete public proof and signature bytes through the in-process
node API, checks ownership/provenance/unproved outputs/proof corruption/replay/
double spending, and spends the actual prior output with its private opening.
The printed payload length includes proofs and authorizations.

Soundness, SHVZK and quantum Fiat-Shamir proofs, independent parameter review,
constant-time implementations, graph privacy and recipient encryption remain
separate research work. Successful boundary tests do not establish those properties.
