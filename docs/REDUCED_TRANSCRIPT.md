# Reduced Linear-Relation Transcript

**Status:** implemented research harness; deliberately not cryptography.

## Purpose

This component turns the PDF-reconciled cycle-masking equations into a runnable
transcript boundary before the full Gao construction is attempted. It uses a
toy scalar modular vector commitment so that the commitment equation can be
exercised end-to-end.

Implementation:

- `pqct/reduced_transcript.py`
- `tests/test_reduced_transcript.py`

## Exact relation

For a width-`k` column vector `c`, the witness relation is:

```text
Σ(j=0..k-1) 2^j c_j = 0
```

The prover samples `d'_0 = d'_k = 0`, derives:

```text
d_j = d'_j - 2*d'_(j+1)
```

and sends a commitment to `d`. After challenge `x`, it responds with:

```text
f_j = x*c_j + d_j
z = x*r_c + r_d
```

The verifier reconstructs `f_0` over the integers, checks the exact weighted
sum, checks bounds, and verifies:

```text
Com(f; z) = x*C + D
```

The challenge binds the protocol domain, key, statement bytes, relation
commitment, and mask commitment through a length-delimited SHA-256 transcript.

## What this proves—and does not prove

Under the toy commitment's binding assumption, this is a reduced linear-relation
transcript. It does **not** prove that the committed coordinates came from
binary amount vectors. The missing partially amortized binary proof is the
component that supplies that property in Gao et al.'s construction.

It is also not lattice-based: the toy commitment is scalar modular arithmetic.
The module exists to test transcript logic, omitted-coordinate handling, exact
integer checks, and mutation rejection before replacing the commitment with the
published lattice construction.

## Randomness and bounds

`SystemIntSampler` uses Python's system CSPRNG for harness experiments.
`SequenceIntSampler` exists only for deterministic tests. The sampler is not
the paper's Gaussian/rejection distribution. No production parameter claim is
made.

## Negative guarantees

This module must not be used for:

- money or private keys;
- production authorization;
- balance encryption;
- consensus;
- claims of post-quantum security;
- claims of a complete Gao implementation.
