# Gaussian Calibration — Research Only

## Purpose

This experiment now has an explicit finite-support reference distribution for the paper's `D_s`-shaped masks. It is designed to measure support, histograms, tail bounds, and rejection behavior before attempting a production sampler.

## Non-claims

- It is not constant-time.
- It is not a production discrete-Gaussian sampler.
- The reported continuous tail bound is not a proof of statistical distance.
- A histogram is not a security estimate.

## Required calibration record

For every proposed profile record:

1. `sigma`, support cutoff, and omitted-tail bound;
2. exact normalized finite-support weights;
3. deterministic seed and sample count;
4. empirical histogram and expected probabilities;
5. rejection majorant and empirical acceptance;
6. numerical precision and implementation version;
7. comparison against an independently written sampler.

The exact `D1/D2/D3` mapping remains blocked until every paper symbol is mapped to a profile and the norm/smoothing argument is independently reconstructed.
