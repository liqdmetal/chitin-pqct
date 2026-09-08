# PQ Account Transition Statement — Draft

This is the first DERO-compatible statement boundary. It is a protocol target, not an implemented proof.

## Public inputs

The verifier must receive a canonical, transcript-bound statement containing:

- protocol version and proof-suite identifier;
- account identifier or account commitment;
- previous encrypted/account-state commitment;
- next encrypted/account-state commitment;
- aggregate debit commitment;
- aggregate credit commitment;
- asset identifier;
- account sequence/nonce;
- transaction identifier and chain/domain identifier;
- any fee or issuance context;
- public authorization key identifier and PQ signature artifact.

The exact public input list is not final until the state-transition rules are mapped from `derohe`.

## Private witness

The prover may know:

- old and new plaintext account amounts;
- debit and credit amounts;
- commitment randomness/opening values;
- recipient recovery material where applicable;
- authorization secret material needed to produce the signature.

Secret keys must not be included in the proof witness unless the selected proof system explicitly requires a proof of knowledge of the signing key. In the first design, authorization remains a separate ML-DSA or hybrid signature check.

## Intended relations

### Conservation

For a non-mint, non-burn transfer:

```text
old_balance + credits = new_balance + debits + fee
```

The proof must bind every term to the public commitments and must define the integer interpretation. Modular equality alone is insufficient because it permits wraparound.

### Range

Every amount must satisfy:

```text
0 <= amount < 2^B
```

`B` is not chosen yet. It must be tied to the maximum account balance, fee policy, issuance policy, and the proof construction’s message space.

### Authorization

The transaction signature must bind the account, sequence/nonce, commitments, proof bytes or proof hash, version, suite identifier, and chain/domain identifier. A valid signature over an incomplete statement is not sufficient.

### Replay and state ordering

The account sequence/nonce must be checked by the ledger and included in the signed and proven context. The proof alone does not provide replay protection.

## Explicit non-goals for v0

- no hidden sender anonymity ring;
- no migration of existing EC balances;
- no claim that the draft is zero-knowledge;
- no claim that commitments are encrypted balances;
- no custom parameter set;
- no consensus changes;
- no use of toy arithmetic for real value.

## Open design questions

1. Does the new state use a public lattice commitment, a lattice encryption ciphertext, or both?
2. How does an account owner recover the next balance without exposing an opening to observers?
3. Is the account state updated by homomorphic addition, ciphertext refresh, or proof-carrying replacement?
4. Which published proof gives the cleanest conservation-plus-range relation without ring machinery?
5. What is the maximum acceptable proof size and verification time for DERO’s block/transaction limits?
6. How are legacy EC balances converted without creating a quantum-exposed migration link?
