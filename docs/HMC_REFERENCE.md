# HMC Reference Component

## Status

Implemented as an isolated, toy-parameter reference component. It is not a
secure commitment, not an encryption scheme, and not consensus-ready.

## Paper mapping

Gao et al. define the hashed-message commitment:

```text
ck = (G_r, G_m)
C = G_r · r + G_m · m
```

where `G_r ∈ R_q^(n×m)` and `G_m ∈ R_q^(n×v)`. The reference module uses the
same shape over the lab's toy ring `Z_q[X]/(X^d + 1)`.

Implemented:

- fixed-dimension public key validation;
- canonical ring-element validation;
- commitment and opening verification;
- additive homomorphism;
- centered coefficient and infinity-norm helpers;
- relaxed-opening boundary `yC = Com(m; r)`;
- canonical key encoding.

## Deliberate exclusions

- secure key generation;
- statistically or computationally justified parameter generation;
- Module-LWE/SIS security;
- rejection-sampling distributions;
- binary proof transcript;
- side-channel resistance;
- production serialization compatibility.

## Research warning

The relaxed opening is an important paper boundary. It must not be replaced by
ordinary opening equality during a Gao-compatible soundness analysis. The
relaxation factor affects extraction and concrete parameter requirements.
