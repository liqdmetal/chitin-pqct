# Blocker Status — Gao Linear-Equation Path

## Closed in the research harness

- PDF-level cycle-masking identity.
- Integer omitted-coordinate reconstruction.
- Exact relation checks before modular reduction.
- Domain-separated challenge transcript.
- Toy commitment response equation.
- Binary-mask coordinate identity:

```text
g_i(x - g_i) = x t_i(1 - 2b_i) - t_i²
```

- Partial-amortization homomorphic opening equation in toy arithmetic.
- Distribution-independent rejection-sampling acceptance equation.
- Public/private commitment separation in the batch-opening test path.

## Remaining research gates

1. Replace toy ring parameters with a reviewed concrete parameter set.
2. Implement exact `D_1`, `D_2`, `D_3` distributions and rejection calibration.
3. Independently re-derive special soundness and SHVZK.
4. Parameter-estimate Module-SIS hardness and completeness failure probability.
5. Add a second independent implementation and vector cross-check.
6. Add balance-recovery encryption, authorization, replay, and shadow-ledger semantics.

The HMC interface and Protocol-1-shaped `E/F/G` transcript now exist as reference components, but they are not claimed to reproduce the paper's full security proof or parameterization.

## Important boundary

The new modules are arithmetic/reference components. Passing tests show that the
implemented equations execute and reject selected mutations. They do not show
that the complete Gao construction is secure, post-quantum, or suitable for
consensus.
