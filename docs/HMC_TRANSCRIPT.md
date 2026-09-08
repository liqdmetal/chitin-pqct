# HMC-Backed Reduced Transcript

## Status

This is the next research integration step: the reduced cycle-masked transcript
now uses the paper-shaped HMC commitment interface instead of the scalar toy
commitment.

It is still **not** a complete Gao proof and has no production-security claim.

## Implemented boundary

```text
C = G_r r + G_m c
D = G_r r_d + G_m d
f = x c + d
z = x r + r_d
Com(f; z) = xC + D
```

The verifier reconstructs the omitted `f_0` over centered integer
coefficients, rejects coefficient wraparound, checks the exact weighted relation,
and then checks the HMC commitment equation.

## Deliberate omissions

- Gao's sparse polynomial challenge space `C`;
- the exact `D_1`, `D_2`, and `D_3` distributions;
- Rej acceptance integration;
- the complete partially amortized binary proof;
- relaxed-opening extraction and security reduction;
- secure parameter generation.

Those omissions are explicit. This module is a bridge between the arithmetic
oracle and the full published construction, not a shortcut around the missing
proof components.
