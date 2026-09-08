# Gao Protocol 1 Extraction — Research Boundary

## Paper equations pinned

From Gao et al., IACR ePrint 2021/1674, Protocol 1 (rendered PDF page 11; text extraction in `vendor/gao-2021-1674.txt`):

```text
zeta <- C
T1 = p * sqrt(2*w*k)
T2 = B*w*p*sqrt(3*m*d)

r_e       <- S_B^m
r_f       <- D_{phi2*T2}^{m*d}
t_i       <- D_{phi1*T1}^{k*d}
r_{t,i}   <- D_{phi2*T2}^{m*d}

E = Com((t_i o (1 - 2*b_i))_{i=0}^{S-1}; r_e)
F = Com((-t_i o t_i)_{i=0}^{S-1}; r_f)
G = Com(sum_i zeta^i*t_i; sum_i zeta^i*r_{t,i})

x <- C
g_i       = x*b_i + t_i
z_g       = x*r_e + r_f
z_{b,i}   = x*r_{b,i} + r_{t,i}
z_b       = sum_i zeta^i*z_{b,i}
```

The verifier checks the displayed response bounds and:

```text
xE + F = Com((g_i o (x - g_i))_i; z_g)
x sum_i zeta^i B_i + G = Com(sum_i zeta^i g_i; z_b)
```

The paper's challenge space is:

```text
C = { x in R : deg(x)=d-1, HW(x)=w, ||x||_inf=p }
```

## Implementation status

- `pqct.binary_protocol1_ring` now derives `zeta` before `E/F/G` and `x` after them;
- both aggregations use ring powers `zeta**i`;
- the ring challenge is negacyclicly multiplied, never coefficientwise;
- `RingProtocol1Parameters.from_paper_bounds` computes the displayed `T1`, `T2`, `g`, `z_g`, and `z_b` bounds;
- `pqct.protocol1_sampling` samples the displayed object dimensions and applies the paper-shaped `Rej` equation;
- `pqct.protocol1_sampled` performs deterministic abort/retry and independently verifies accepted transcripts.

## Explicit boundary

The sampler uses finite-support reference Gaussians, not a constant-time production sampler. The exact paper distribution convention, statistical-distance target, relaxed-opening extractor, SHVZK simulator, and concrete Module-SIS/LWE estimate remain open. Passing synthetic transcript tests is not a security proof.
