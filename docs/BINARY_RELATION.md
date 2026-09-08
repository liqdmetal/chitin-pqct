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

## What is implemented (equations 39, 41-45)

`pqct.protocol1_binary_relation.verify_binary_relation_equations_38_45`
mechanically checks the paper's downstream algebra given the TRUE
witness `b_{i,j}`, `t_{i,j}` and the extracted `e^_{i,j}`, `s^_{i,j}`
(caller-supplied, not derived from commitments):

- eq.(39)/(41): `y*h_{i,j} = x*e^_{i,j} + s^_{i,j}` mod q at 3 transcripts.
- eq.(42)-(44): the unreduced (over R, not R_q) integer system built from
  `g_{i,j} = x*b_{i,j} + t_{i,j}`, one row per transcript, with the
  common quadratic-in-x coefficient `u = b_hat*(Y - b_hat)`,
  `Y = y*y_zeta`, `b_hat = Y*b_{i,j}`, `t_hat = y_zeta*t_{i,j}`.
- eq.(45): `D*u = 0` in R, `D` the Vandermonde factor
  `(x0-x1)(x0-x2)(x1-x2)`, checked directly.

It is a BOUNDED ORACLE, not an extractor: it takes the true bit as
input and checks the paper's claimed identities hold (or, for a
non-binary bit, that eq.(41) at the third transcript and everything
downstream fails, matching the paper's soundness argument). It does
NOT derive `b_{i,j}` from ciphertexts/commitments -- see
`equation_38_40_note` in the module for what eq.(38)/(40)'s
zeta-unbatching step would additionally require.

The scaling `b_hat = y*y_zeta*b` (not `y_zeta*b`) was verified against
the paper's closing statement (line 2273) with an independent integer
script before being encoded; using the wrong scaling silently breaks
eq.(44) even for a genuinely binary witness. See
`docs/HARD_BLOCKER_PROGRESS.md` for what remains (the full-unbatching
extractor and the zero-divisor gap between "D*u=0 in R" and "u=0").

## What is still NOT implemented

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