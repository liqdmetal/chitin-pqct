# Balance-conservation composition oracle

`pqct.balance_composition` wires Gao Section 4's balance machinery
(amount decomposition + per-column conservation + cycle masking) into an
executable reference oracle.

## What it does

- `SignedAmount`: a value plus conservation sign (+1 credit, -1 debit).
- `build_balance_columns`: decomposes each amount to bits and computes
  `c_j = sum_i sign_i * bit(amount_i, j)` per column (Gao eq. 14).
  Conservation holds iff `sum_j 2^j c_j == 0` exactly.
- `build_masked_balance_response`: applies the cycle-masking identity
  (Gao eq. 15 / Protocol 2) so the weighted masked response is exactly
  zero over the integers.

This is the corrector-free balance claim (Gao Section 4.1): with no
corrector values or range proofs, integer-conserved amounts that each
fit the bit width give an exact integer zero relation.

## Bug found while building

The first implementation zipped the per-amount signs against the
per-bit-column sums, silently truncating to the shorter length and
producing a wrong relation. Caught by the very first test run (columns
came back length 3 instead of 8). Fixed by summing signs per column.

## Boundary

Reference oracle only. Not a complete lattice balance proof: no
rejection sampling, no soundness reduction, no commitment of the amount
bits actually linked to a Protocol 1 transcript yet. Still synthetic
research; no testnet/production use.
