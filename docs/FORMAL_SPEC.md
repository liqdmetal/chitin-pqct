# Formal Reference Specification — Linear-Equation Component

**Status:** arithmetic reference specification; not a complete proof system.

## Source boundary

The equations below are transcribed from Section 4 and Protocol 2 of Gao et al.,
IACR ePrint 2021/1674, using the downloaded PDF rather than HTML extraction.
The partially amortized binary proof (`P_bin`) and the homomorphic commitment
(`Com_ck`) remain separate dependencies and are not implemented here.

## Statement

Given public integers `ω_0, ..., ω_{S-1}`, the prover knows binary vectors
`b_i ∈ {0,1}^k` such that:

```text
F(b_0, ..., b_{S-1}) = Σ_i ω_i · <2^k, b_i> = 0.
```

Define the bit-column relation:

```text
c_j = Σ_i ω_i · b_{i,j}
```

Then the relation is:

```text
Σ_{j=0}^{k-1} 2^j c_j = 0.
```

The verifier can derive the commitment to `c` from public bit commitments:

```text
C = Σ_i ω_i B_i.
```

## Cycle masking

The prover samples an auxiliary vector `d'` with endpoints zero:

```text
d'_0 = d'_k = 0.
```

For `j = 0, ..., k-1`, derive:

```text
d_j = d'_j - 2 d'_{j+1}.
```

Therefore:

```text
Σ_j 2^j d_j = d'_0 - 2^k d'_k = 0.
```

After Fiat–Shamir challenge `x`, form:

```text
f_j = x c_j + d_j.
```

Thus:

```text
<f, 2^k> = x <c, 2^k> + <d, 2^k> = 0.
```

The verifier reconstructs the omitted first coordinate over the **integers**:

```text
f_0 = -Σ_{j=1}^{k-1} 2^j f_j.
```

It must then check that `f_0` is representable in the ring and that all
published response norms and commitment equations satisfy the construction's
bounds. Checking only modulo `q` is insufficient.

## Account specialization

For the first account-mode model, use public weights:

```text
(+1 old_balance, +1 credits, -1 new_balance, -1 debits, -1 fee)
```

Each amount is decomposed into exactly `B` bits and is required to satisfy:

```text
0 <= amount < 2^B.
```

This is an arithmetic relation only. It does not yet provide encryption,
ownership, authorization, replay protection, or a zero-knowledge proof.

## Required missing components

Before claiming a Gao-compatible implementation, resolve and implement against
the paper exactly:

1. `Com_ck` dimensions, distributions, and hiding/binding assumptions;
2. the complete partially amortized binary proof;
3. `Rej` distributions and acceptance probabilities;
4. all norm bounds and completeness error;
5. Fiat–Shamir transcript and challenge domain;
6. serialization and parameter generation;
7. security reduction and concrete parameter estimator.
