# HMC binding reduction (Gao Lemma 1 / Equation 2)

`pqct.hmc_binding_reduction` mechanically implements Gao's stated
strong-binding reduction, not just a restatement of the claim.

## What it does

Given an accepted HMC collision `(m0,r0) != (m1,r1)` with
`Comck(m0;r0) = Comck(m1;r1)`, `derive_msis_solution` builds
`z = (m1-m0, r1-r0)`, verifies `G.z = 0` literally (not assumed), and
reports `beta = ||z||_inf` (via `infinity_norm`). This is a real
M-SIS(n, m+v, q, beta) solution instance, matching paper text lines
312-317: any HMC collision directly gives such a solution.

`check_binding_parameters` evaluates Equation (2):

```text
min(q, 2^(2*sqrt(n*d*log2(q)*log2(delta)))) > beta
```

the paper's stated NECESSARY condition for beta-binding, given a
concrete `(n,d,q,delta,beta)`.

## Boundary

This does not establish M-SIS hardness itself (that needs the lattice
estimator, see `docs/LATTICE_ESTIMATE.md`), nor does it prove the full
computational-binding reduction in the general (non-collision) case --
only the mechanical collision-to-SIS-solution step and the Eq.(2)
parameter check are implemented. No production, testnet, or mainnet
use is authorized.

## Verification

6 tests in `tests/test_hmc_binding_reduction.py`: real collision ->
valid M-SIS solution, non-collision rejected, invalid delta rejected,
Eq.(2) pass/fail on small/huge beta.
