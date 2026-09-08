# Independent Protocol 1 Oracle

## Purpose

`pqct.protocol1_independent_oracle` is a structurally independent raw-tuple
oracle for Gao et al. Protocol 1. It does not import `RingElement`, `HMCKey`,
`build_protocol1_ring_transcript`, or `verify_protocol1_ring`.

It independently implements:

- negacyclic polynomial multiplication through the existing tuple oracle;
- raw matrix commitments;
- `E`, `F`, and `G` construction;
- `g_i = x b_i + t_i`;
- `z_g = x r_e + r_f`;
- `z_{b,i} = x r_{b,i} + r_{t,i}`;
- `z_b = Σ ζ^i z_{b,i}`;
- both public verifier equations.

## Boundary

This oracle is intentionally not a complete prover. It does not implement:

- Fiat–Shamir derivation;
- exact paper distributions;
- rejection sampling;
- norm bounds;
- HMC hiding or binding;
- soundness or SHVZK proofs;
- concrete security parameters.

Its value is differential testing: a hand-constructed transcript is built and
verified using raw coefficient tuples, then compared against the main ring path.
A local prover/verifier pair passing is not treated as independent evidence.

## Tests

`tests/test_protocol1_independent_oracle.py` verifies:

- an independently constructed transcript is accepted;
- response mutation is rejected;
- challenge mutation is rejected;
- the raw key is not the local HMC key type.
