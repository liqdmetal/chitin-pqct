# Fixed-challenge SHVZK comparison laboratory

`pqct.protocol1_shvzk_compare` compares finite toy honest and witness-free simulator transcript generators at fixed `(zeta, x)`.

## Marginal (per-coefficient) comparison — corrects the birthday-bound artifact

Full response/transcript tuples live in an astronomically large space, so
exact-tuple TV=1 is expected regardless of whether the underlying honest and
simulator laws actually match (a birthday-bound artifact, not evidence of a
real mismatch). To get a genuine signal we compare per-coefficient marginals
of accepted `g` and `z_g` values (small bounded integer support, real
collisions occur).

Measured (512 samples, toy fixture, honest 22.66% acceptance):

```text
g:  honest mean=-0.0506 var=7.78 (n=928)
    sim    mean=-0.0073 var=7.74 (n=4096)
    exact TV = 0.052
z_g: honest mean=0.138 var=24.33 (n=928)
     sim    mean=0.091 var=23.60 (n=4096)
     exact TV = 0.075
```

Variances match closely (calibration is roughly right). TV is small (0.05-0.08),
not the ≈1 from full-tuple comparison. Means differ somewhat; this may be
finite-sample noise (honest n=928 vs sim n=4096) or a real bias term from
`g = x*b + t` mixing with bit values `b in {0,1}`, absent in the surrogate.
Not yet resolved — flagged, not fixed by tuning.

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

## Boundary

This remains a finite toy experiment. It does not establish Gao's exact
`D_1/D_2/D_3` law, Lemma 6, SHVZK, computational indistinguishability,
soundness, Fiat-Shamir security, or production security. No production,
testnet, or mainnet use is authorized by this or any prior result in this
repository.
