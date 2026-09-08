# Security Games — HMC Reference Boundary

This document freezes the games that the eventual lattice implementation must
satisfy. It is a specification target, not a proof.

## HMC hiding

1. Generate `ck = (G_r, G_m)` with the declared parameter distribution.
2. The adversary chooses equal-length messages `m_0, m_1`.
3. Sample `b` uniformly, randomness `r`, and return `C = Com_ck(m_b; r)`.
4. The adversary outputs `b'`.

Advantage is `|Pr[b'=b] - 1/2|`. The reduction must identify the exact
Module-LWE instance and account for all dimensions and distributions.

## Strong binding

The adversary outputs two openings `(m_0,r_0)` and `(m_1,r_1)` for one `C`.
Acceptance requires both openings to pass the declared norm bound and `m_0 !=
m_1`. The reduction maps the collision to a short Module-SIS witness.

## Linear-relation knowledge soundness

The adversary receives public commitments `B_i`, produces an accepting
transcript for the same first message under two distinct challenges, and the
extractor must recover the declared relaxed opening relation. Ordinary modular
subtraction is not enough: challenge differences may be non-invertible and the
relaxation factor changes the bound.

## Zero knowledge

The simulator must produce a transcript statistically or computationally close
to a real transcript without the committed bits or relation witness. The proof
must account for rejection sampling and the exact challenge space.

## Implementation obligations

Every game requires:

- canonical serialization;
- domain and statement binding;
- exact norm definitions;
- failure-probability accounting;
- multi-instance and multi-user treatment;
- a declared quantum model for Fiat–Shamir claims.
