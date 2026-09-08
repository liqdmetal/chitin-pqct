# Lattice hardness estimate (core-SVP methodology, NOT the real tool)

`pqct.lattice_estimate` chains: Gao's own Equation (2) -> required
root Hermite factor delta -> BKZ blocksize (Chen-Nguyen 2011
approximation) -> core-SVP bit cost (Albrecht/Player/Scott 2015
sieving constants, the same convention NIST PQC submissions use).

This is a standard, widely-cited estimation METHODOLOGY, not a
substitute for the verified Albrecht/Player/Scott `lattice-estimator`
tool (unavailable in this environment; needs native fpylll/Sage
libs). It ignores dual attacks, hybrid attacks, BKZ 2.0 simulators,
and exact GSA slope -- all present in the real tool.

## Important dimensional bug found while wiring this up

Gao Definition 1: `M-SIS(n, m, q, beta)` -- `n` is the MODULE RANK
(rows of the SIS matrix over R_q), independent of `d` (ring degree).
`pqct.parameterization.ParameterCandidate` (the toy-ntt-32/64
fixtures) uses `n` for the RING degree only and has no separate
module-rank field, so `n == d` for those candidates by construction.
Feeding that conflated value into `estimate_sis_hardness(n=c.n, ...)`
computes a number, but it is NOT a meaningful SIS-rank-sensitive
hardness estimate. `tools/estimate_parameters.py` now runs both:
the toy candidates (explicitly labeled CONFLATED) and
`GaoPaperProfile` (n=29, d=64, independent -- labeled CORRECT).

## Measured (toy fixtures + paper-reported profile)

```text
toy-ntt-32   (CONFLATED n=d=32):  classical ~965 bits
toy-ntt-64   (CONFLATED n=d=64):  classical ~4618 bits
gao-paper    (CORRECT n=29,d=64): classical ~8974 bits
```

All at illustrative small beta_bound values (256-1024), not the
paper's own derived T1/T2 response bounds -- these numbers describe
the ESTIMATOR's behavior on example inputs, not a certified security
level for any deployed parameter set.

## Boundary

No production, testnet, or mainnet use, and no "128-bit PQ" claim is
authorized by any number in this file or its outputs.

## Verification

7 tests in `tests/test_lattice_estimate.py`: delta/beta round-trip,
monotonicity, model ordering (classical>quantum>paranoid), domain
rejection, and finite outputs on both toy dimension sets.
