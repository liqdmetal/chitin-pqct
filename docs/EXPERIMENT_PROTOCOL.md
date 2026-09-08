# PQ-CT Experiment Protocol — v0.1

## Purpose

Run the isolated reference harness as a research experiment. This protocol does not authorize money, private keys, wallets, consensus, or deployment.

## Parameter lanes

### Lane A — toy executable

- `ToyProfile`: small ring, bounded scalar challenge, zero claimed security.
- Purpose: exhaustive checks, mutation tests, transcript debugging, and differential vectors.

### Lane B — paper-record profile

- `GaoPaperProfile`: records the paper's reported evaluation values.
- Purpose: parameter provenance and reproducibility bookkeeping only.
- It is not wired into the toy prover and does not inherit the paper's security claim.

### Lane C — proposed production candidate

Not present. It requires an external estimator, exact distributions, a reviewed challenge sampler, proof-level accounting, and independent implementations.

## Launch checklist

Before each experiment:

1. Run the full test suite from a clean working tree snapshot.
2. Record Python version, profile name, parameter values, test count, and commit/hash.
3. Confirm the experiment imports no DERO consensus package.
4. Confirm no real keys, balances, wallet files, or network endpoints are used.
5. Store generated vectors with profile provenance and a domain-separated format tag.
6. Treat every failure as a research issue; do not weaken a verifier or enlarge a bound to make a vector pass without recording why.

## Required experiment families

- honest transcript generation and verification;
- one-field-at-a-time transcript mutation;
- nonbinary witness mutation;
- commitment/opening substitution;
- statement/context substitution;
- modular-wraparound attempts;
- boundary norm values;
- rejection-sampler acceptance distribution;
- tiny-ring exhaustive search;
- independent implementation vector comparison.

## Stop conditions

Stop the experiment and open a finding if:

- a malformed proof verifies;
- two encodings represent the same accepted statement;
- a paper-profile value is silently used by a toy profile;
- a rejection sampler accepts outside its declared majorant;
- an integer relation is accepted only because of modular reduction;
- any code path touches DERO consensus or wallet state.

## Current result

The current isolated lab passes its Python suite. This demonstrates harness consistency only. It does not establish soundness, zero knowledge, hiding, binding, or post-quantum security.
