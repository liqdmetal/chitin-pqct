# Intermediate integer/modular-wraparound audit

`pqct.protocol1_integer_trace` runs a parallel coefficient-level calculation in
`Z[X]/(X^d+1)` beside the ring implementation in `R_q`. It records challenge
powers, `g`, `h=g(x-g)`, `x h`, response products, weighted aggregation, and
the pairwise second-layer expressions.

A report is `safe` only when every recorded coefficient remains strictly inside
the centered interval (`2*abs(value) < q`) and the canonical reduction matches
the supplied ring value. A `safe` report is not a proof: all protocol operations
are not yet instrumented, and small toy values do not establish parameter-level
bounds.

The test suite includes a deliberately small-modulus fixture that produces an
intermediate wraparound and is rejected by the audit. Current full verification
runs 106 tests.
