# Goodness-of-fit testing (chi-square, pure stdlib)

`pqct.goodness_of_fit` adds a real statistical test the project lacked:
whether a sampler's empirical output actually matches its OWN claimed
discrete PMF. Previously only pairwise (honest-vs-simulator) marginal
comparisons existed -- neither side was ever checked against its own
claimed law.

## What it is

- A pure-stdlib regularized incomplete gamma function (series +
  continued-fraction, Numerical Recipes 6.2), used to compute the
  chi-square survival function (p-value) with no scipy/numpy dependency
  in `pqct` itself. Cross-checked against `scipy.stats.chi2.sf` in
  `tests/test_goodness_of_fit.py` -- max observed error 3e-15 over 300
  random `(statistic, df)` pairs (scipy used ONLY as a verification
  oracle in tests; the library code has zero external dependencies).
- `chi_square_goodness_of_fit(observed_counts, expected_probabilities)`:
  merges low-expected-count bins (Cochran's rule, min_expected=5 default)
  so the asymptotic chi-square approximation stays valid, then reports
  the statistic, degrees of freedom, and p-value.

## Real result: t_i masks fit their own claimed law

`tools/check_mask_goodness_of_fit.py` draws 20,000 `t_i` mask
coefficients from `sample_protocol1_masks` and tests them against
`FiniteDiscreteGaussian(phi1*T1, tail)` -- the exact claimed law for
`t_i` (unlike `g=x*b+t` or `z_g=x*r_e+r_f`, which are shifted/mixed,
`t_i` is drawn directly from this profile with no further transform).

```text
sigma=27.71, T1=13.86, samples=20000, bins=25, df=24
chi_square_statistic=16.63
p_value=0.864
verdict: FAILS to reject fit (p>=0.01)
```

This is a genuine machine-checked fact: the finite-support sampler's own
inverse-CDF output matches its own claimed PMF within statistical noise.

## Boundary

This tests SELF-CONSISTENCY (does the sampler match its own math), not
Gao's exact infinite discrete-Gaussian D_sigma law, the paper's claimed
2^-100 statistical-distance target, or SHVZK/soundness/Fiat-Shamir
security. A finite-support sampler matching its own truncated PMF says
nothing about how close that truncated PMF is to the infinite one --
see `pqct.statistical_distance` for the separate truncation-TV bound
work. No production, testnet, or mainnet use is authorized by this
result.
