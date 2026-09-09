# Lattice balance transcript (amount bits -> HMC -> Protocol 1)

`pqct.balance_transcript` is the composition layer that wires the integer
balance oracle (`balance_composition`) to real protocol objects.

## What it does

For a transaction of signed amounts (+1 credits, -1 debits), each with
value < 2^bit_width:

1. Decomposes each amount to bits; commits `B_i = Com(b_i; r_{b,i})`
   under the HMC base key (openings sampled from S_B^m).
2. Runs a REAL sampled Protocol 1 binary proof per amount
   (`prove_protocol1_ring_sampled`: two-stage rejection + abort/retry +
   independent verification). Each amount gets its OWN proof because
   `RingProtocol1Parameters` caps `max_vectors <= 2` (paper's S<=2
   scope); multi-amount batching is not used.
3. Combines homomorphically per Gao eq.(11):
   `C_c = sum_i sign_i * B_i` and checks
   `C_c = Com(c; sum_i sign_i * r_{b,i})` where c_j is the signed
   bit-column sum -- the verifier-computable commitment to the
   conservation vector.
4. Checks conservation as the exact integer relation
   `sum_j 2^j c_j == 0` (Gao eq.10/14, corrector-free claim).

## What it does NOT do

- The conservation equation is checked at INTEGER level against the
  witnesses, not proven in zero knowledge. A ZK conservation proof is
  Gao's Protocol 5 inner-product argument (`<f, 2^k> = dsum` + cycle
  masking over ring elements); that remains unimplemented.
- No replay/state binding, no authorization, no recovery encryption.
- Toy parameters only; not a security claim.

## Verified behavior

7 tests: conserved 3-amount transaction composes with all proofs
accepted; non-conserved transaction flags conservation=False while the
eq.(11) combination check still holds (orthogonal checks); tampered
column vector breaks the combination opening; out-of-range amount,
empty seed, bit-width mismatch rejected; deterministic reproducibility.

## Boundary

Synthetic research only. No production, testnet, or mainnet use; no
real balances. See docs/TESTNET_SCOPE.md for what a testnet would
actually require.

