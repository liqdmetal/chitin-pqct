# Lemma 6 completeness-error validation

Gao's Theorem 1/2 claim SHVZK "with a completeness error 1 - 1/(mu(phi_1)mu(phi_2))"
(Lemma 6) -- equivalently, the honest prover's ACCEPTANCE PROBABILITY should be
`1/(mu(phi_1)*mu(phi_2))`. That is a **quantitative, falsifiable prediction**
about the harness, not a property to be assumed.

`tools/check_completeness_error.py` measures the real acceptance rate of the
Protocol 1 rejection path over many samples and tests it against the formula
with a Wilson 95% score interval.

## Measured result (600 samples per phi, phi_2 = 2)

```text
phi1   measured   predicted 1/(mu1*mu2)   Wilson 95% CI        covered
 1     0.2600     0.2528                  [0.2265, 0.2965]     YES
 2     0.4717     0.4724                  [0.4320, 0.5117]     YES
 4     0.5833     0.5879                  [0.5435, 0.6221]     YES

all_phis_consistent: true
```

The paper's formula predicts the harness's measured acceptance rate within
statistical noise at every phi tested. Acceptance also rises monotonically
with phi (wider mask -> fewer rejections), matching the mechanism.

This is the first QUANTITATIVE cross-check of a Gao theorem claim against
actual harness behavior (earlier checks were algebraic/structural).

## What it is and is not

- IS: evidence the finite-support rejection sampler implements the
  Lyubashevsky mu(phi) acceptance law the paper's completeness argument
  relies on.
- IS NOT: a proof of Lemma 6, SHVZK, or any security property. The sampler
  is finite-support (not the paper's exact infinite D_sigma), so agreement
  is consistency-with, not equivalence-to, the claimed law. The mu(phi)
  convention is shared with RejectionPolicy.mu, so this validates the
  harness against the formula, not the formula against reality.

## Unit coverage

`tests/test_completeness_error.py` locks the pure helpers
(`predicted_acceptance`, `wilson_interval`) independent of the slow
sampling path: formula match, monotonicity in phi, interval coverage and
narrowing, edge cases.

## Boundary

Synthetic research only. No production, testnet, or mainnet use.
