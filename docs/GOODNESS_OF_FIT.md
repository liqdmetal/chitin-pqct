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

## Real result: ACCEPTED honest g/z_g/z_b,i samples fit the paper's law

`tools/check_accepted_goodness_of_fit.py` tests Gao's actual Theorem 1
completeness claim (paper text lines 2030-2031): after Rej() acceptance,
`g_{i,j}` should be statistically close to `D_{1,T1}^d` and
`(z_g,(z_b,i))` close to `D_{2,T2}^{md}`.

```text
g:    p=0.796 (n=464, df=12)   FAILS to reject fit
z_g:  p=0.494 (n=464, df=60)   FAILS to reject fit
z_b,i: p=0.921 (n=464, df=60)  FAILS to reject fit
```

All three claimed laws survive this falsification attempt.

### A bug I found and fixed in the TEST TOOL, not in pqct

The first two runs (gaussian_tail=9, then a mis-scaled 60/40 with wrong
per-parameter tails) gave `z_g`/`z_b,i` p-values of ~1e-118 and ~1e-139 --
apparent hard rejection. Root cause: `gaussian_tail=9` against z_g's true
`sigma=phi2*T2~19.6` truncated the support to well under half a standard
deviation, so the finite sampler was drawing from a near-flat/boxy
window, not anything resembling a Gaussian shape at all (verified
directly: weight at the tail boundary was 90% of the peak weight,
confirming near-uniformity). This was a parameter-choice bug in the
TEST SCRIPT'S fixture, not a bug in `pqct.protocol1_sampling` or
evidence against the paper's claim. Fixed by widening `gaussian_tail`
to 60 (t_profile and opening_profile currently share one tail parameter
in `Protocol1DistributionParameters` -- a real, separate limitation
worth fixing upstream so tests don't have to hand-tune a shared value).

## Boundary

This tests SELF-CONSISTENCY (does the sampler match its own math), not
Gao's exact infinite discrete-Gaussian D_sigma law, the paper's claimed
2^-100 statistical-distance target, or SHVZK/soundness/Fiat-Shamir
security. A finite-support sampler matching its own truncated PMF says
nothing about how close that truncated PMF is to the infinite one --
see `pqct.statistical_distance` for the separate truncation-TV bound
work. No production, testnet, or mainnet use is authorized by this
result.
