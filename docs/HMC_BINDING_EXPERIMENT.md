# Bounded HMC binding experiment

`pqct.hmc_binding_experiment` exhaustively searches tiny centered difference boxes for
relaxed collisions

```text
y · (G_m Δm + G_r Δr) = 0 in R_q^n.
```

It records actual collision witnesses and the number of checked tuples. This is a
falsification tool only:

- no Module-SIS reduction;
- no hardness estimate;
- no extrapolation from an empty toy box;
- no statement about the generated matrix family at real dimensions;
- no production or 128-bit security claim.

A zero-relaxation test intentionally finds collisions. A nonzero test can show that
one small box has no collision for one explicit toy key, but cannot establish binding.
