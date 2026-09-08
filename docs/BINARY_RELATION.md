# Binary-relation extraction (Gao equations 38-45)

STATUS: partial, not complete.

## What's implemented

`pqct.protocol1_binary_relation.extract_binary_witness_row` derives a relaxed
bit `b_{i,j}` directly from two accepting transcripts' `g_{i,j}(x)` values.
`g_{i,j}(x) = x*b_{i,j} + t_{i,j}` is per-(i,j) in the public transcript --
unlike `z_b`, it is never zeta-aggregated (paper text lines 2163-2211),
so no unbatching step is required.

```text
y*b_{i,j} = g_{i,j}(x0) - g_{i,j}(x1),  y = x0 - x1
```

## What is NOT implemented (the actual hard part)

The paper's equations (38)-(45) go further: they use THREE distinct x
challenges to build a linear system in the unreduced ring R (not R_q),
argue the Vandermonde determinant is nonzero, and derive
`b_{i,j}*(y_zeta^2 - b_{i,j}) = 0` as an INTEGER (not mod-q) equality,
which forces `b_{i,j} in {0, y_zeta^2}` since challenges are distinct.
This requires the first-layer (zeta-difference) relaxation, NOT just the
second-layer (x-difference) `y` this module computes, plus per-index
`t_{i,j}` unbatching machinery that does not currently exist in the
codebase, plus the existing `pqct.protocol1_integer_trace` unreduced
arithmetic to verify the equality at the integer level rather than mod q.
None of that is implemented yet. This module implements ONLY the
divided-difference part of the argument.

## Independent derivation

A delegated subagent independently derived the paper's symbol mapping
onto pqct's existing extraction primitives (SecondLayerExtraction /
FirstLayerExtraction / SecondLayerPairExtraction), confirmed the paper
overloads 'y' for two distinct relaxation factors (x-side and
zeta-side), and flagged the mod-q vs mod-R distinction as the main
remaining risk of a silent sign/scope error if implemented carelessly.
Full derivation:
`AppData\Local\hermes\cache\delegation\subagent-summary-0-20260908_025709_985013.txt`

## Boundary

Not a soundness proof. No production, testnet, or mainnet use.