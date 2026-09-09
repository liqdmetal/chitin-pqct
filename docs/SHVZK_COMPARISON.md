# Fixed-challenge SHVZK comparison laboratory

`pqct.protocol1_shvzk_compare` compares finite toy honest and witness-free simulator transcript generators at fixed `(zeta, x)`.

## Marginal (per-coefficient) comparison — corrects the birthday-bound artifact

Full response/transcript tuples live in an astronomically large space, so
exact-tuple TV=1 is expected regardless of whether the underlying honest and
simulator laws actually match (a birthday-bound artifact, not evidence of a
real mismatch). To get a genuine signal we compare per-coefficient marginals
of accepted `g`, `z_g`, and `z_b,i` (per-index, pre-aggregation) values
(small bounded integer support, real collisions occur).

Measured (512 samples, toy fixture, honest 22.66% acceptance):

```text
g:  honest mean=-0.0506 var=7.78 (n=928)
    sim    mean=-0.0073 var=7.74 (n=4096)
    exact TV = 0.052
z_g: honest mean=0.138  var=24.33 (n=928)
     sim    mean=0.091  var=23.60 (n=4096)
     exact TV = 0.075
```

zb,i (per-index, pre-aggregation) added later:

```text
zb,i: honest mean=0.308  var=22.73 (n=928)
      sim    mean=0.013  var=23.36 (n=4096)
      exact TV = 0.065
```

Variances match closely across all three quantities (calibration is roughly
right). TV stays small (0.05-0.08) for all three, not the ≈1 from full-tuple
comparison. Means differ somewhat on all three, largest gap on `z_b,i`
(0.308 vs 0.013); this may be finite-sample noise (honest n=928 vs sim
n=4096) or a real bias term the surrogate does not model (e.g. `g = x*b + t`
mixing with bit values `b in {0,1}`, or `z_b,i = x*r_b,i + r_t,i` mixing
with the actual opening randomness `r_b,i` rather than an independent
symmetric draw). Not yet resolved — flagged, not fixed by tuning.

Gao Protocol 1 Step 10 rejects the pre-aggregation tuple

```text
(z_g, (z_b,i)_i)
```

against

```text
x . (r_e, (r_b,i)_i)
```

The public proof exposes only the aggregated `z_b = Sum_i zeta^i z_b,i`. The
harness now constructs the honest path's exact per-index tuple independently
(`build_rejection_tuple_audit`) and gates honest acceptance through the real
`Rej()` two-stage decision (`build_rejection_plan`), not a placeholder.

## Simulator has no rejection gate

Per Gao Appendix B's SHVZK proof: the simulator samples
`g_i,j ~ D_{1,T1}^d` and `(z_g,(z_b,i)) ~ D_{2,T2}^{md}` directly from the
target laws -- these are what honest `Rej()` acceptance is claimed to converge
to (Lemma 6). There is no separate simulator-side rejection stage. Simulator
"acceptance" in this harness is therefore purely the verifier's public
equation/norm check, which the simulator satisfies by construction -- hence
`simulator_acceptance_rate = 1` and `simulator_mean_log_acceptance = None`
(no gate exists to log a probability for).

## Fixed anomaly: -Infinity mean log-acceptance

`accept_rejection` deliberately returns `probability = 0` (so `log(0) =
-Infinity`) for any rejected candidate whose shift fell outside the paper's
stated support condition. The comparison loop previously appended this value
into `honest_logs` unconditionally, before checking whether the sample was
actually accepted. A single -Infinity in that list poisons the mean.
Fixed: `honest_logs` now only receives an entry when `plan.accepted` is
`True`, at which point `accept_rejection`'s own gating already guarantees a
finite, non-zero probability. Regression test:
`test_honest_mean_log_acceptance_excludes_rejected_samples` in
`tests/test_protocol1_shvzk_compare.py`.

## Current toy result (256 samples)

```text
honest_acceptance_rate:        0.2265625
simulator_acceptance_rate:     1
honest_mean_log_acceptance:    -1.2435...  (finite; exp(-1.2435) ~= 0.288)
simulator_mean_log_acceptance: None
conditioned_response_tv:       ~1
conditioned_transcript_tv:     ~1
```

Even restricted to accepted transcripts only, the honest and simulator
response/transcript distributions remain statistically distinguishable
(`conditioned_*_tv ~= 1`) in this toy configuration. This is an honest
falsification signal: the simulator's response surrogate does not yet match
Gao's calibrated `D_1,T1` / `D_2,T2` shape closely enough for
indistinguishability. It is not evidence against Gao's theorem -- the surrogate
sampling parameters, not the theorem, are the suspect.

## CORRECTION: the above "distinguishable" reading was too pessimistic

The `conditioned_*_tv ~= 1` is the SAME full-tuple birthday-bound artifact
described at the top of this file, not evidence of a real law mismatch. The
sharp per-coefficient test is `tools/shvzk_phi_sweep.py`, which measures the
honest marginal AT A WITNESS-BEARING POSITION (a bit=1 coordinate, where
honest `g = x*b + t` carries a real `+x` shift that Lyubashevsky rejection
must flatten back toward `D_{1,T1}`).

Measured (400 samples/phi, x=unit so raw shift is +1 on coeff 0):

```text
WITNESS position (0,1), bit=1:
  phi=1  honest_mean=-0.037  sim=-0.053  gap z=+0.15  accepts=95/400
  phi=2  honest_mean=-0.075  sim=-0.087  gap z=+0.07  accepts=175/400
  phi=4  honest_mean=-0.126  sim=-0.190  gap z=+0.20  accepts=225/400
  phi=8  honest_mean=-0.348  sim=-0.380  gap z=+0.05  accepts=243/400
  flattened: True   (no honest mean anywhere near the +0.125 raw-shift value)
```

The honest mean is nowhere near the `+1/n`-scale raw witness shift it would
carry WITHOUT rejection; it tracks the simulator within finite-sample noise
(|z| <= 0.20 at every phi). Acceptance rises with phi (95->243/400), matching
the wider-mask-means-fewer-rejects prediction. This is the rejection-sampling
mechanism of Lemma 6 visibly working in the toy harness: Rej flattens the
witness-dependent shift so accepted honest g matches the simulator's direct
D_{1,T1} draw.

This does NOT prove SHVZK. It shows the first-moment behavior is consistent
with the claimed mechanism at one witness position over four phi values; a
full indistinguishability argument needs the exact infinite-D_sigma law, the
complete joint distribution, and the computational-hiding reduction for E.

## Boundary

This remains a finite toy experiment. It does not establish Gao's exact
`D_1/D_2/D_3` law, Lemma 6, SHVZK, computational indistinguishability,
soundness, Fiat-Shamir security, or production security. No production,
testnet, or mainnet use is authorized by this or any prior result in this
repository.
