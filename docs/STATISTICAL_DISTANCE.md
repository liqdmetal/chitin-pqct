# Statistical-distance progress

## Implemented bounded facts

`pqct.statistical_distance` now records conservative total-variation bounds for
finite-support discrete Gaussians:

- exact retained finite normalizer;
- discrete geometric upper bound for omitted two-sided mass;
- truncation TV bound `U/(Z_T+U)`;
- independent-coordinate product/union bound;
- ideal inverse-CDF uniform-grid quantization bound;
- conservative bound after rejection conditioning when a common acceptance lower
  bound is known.

These are distributional bounds for the reference sampler only. They do **not**
show that the current profiles equal Gao's exact `D_1`, `D_2`, or `D_3`, and do
not prove the paper's Lemma 6, SHVZK, soundness, or Fiat--Shamir security.

## Unresolved numerical issue

The sampler uses Decimal inverse-CDF arithmetic. The ideal grid bound does not
cover Decimal exponent, summation, or comparison rounding. A separate high-
precision/reference implementation and rounding envelope are still required.

## Rejection issue

Conditioning can amplify a base distribution error. The current helper requires
an explicit lower bound on both acceptance probabilities; measured acceptance
rates alone are not such a bound. The two Protocol 1 rejection stages must be
analysed jointly, with the exact response/shift law and the same event in both
experiments.
