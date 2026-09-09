# Paper-exact bounds + parameter validation

Two modules that replace earlier ad-hoc "research placeholder" bounds with
Gao et al. 2021/1674's OWN published formulas.

## pqct.paper_bounds

Formulas transcribed from the PDF at 500 dpi (two independent transcriptions
agreed), covering Theorem 1 (Protocol 1) and Theorem 2 (Protocol 5):

- `mu_phi(phi)` = exp(1/(2 phi) + 1/(2 phi^2)) -- Lemma 6 / Algorithm 1
  (same convention as RejectionPolicy.mu)
- `kappa_for_s(S)` = S(S-1)/2
- `protocol1_q_precondition_holds` -- q/2 > 16 (w phi_1)^2 p k d
- `gamma_bin` = 4 p^2 sqrt(d^3 w^3 (32 d p^2 k^3 phi_1^4 + 3 phi_2^2 B^2 m^2))
- `relation_rbin_bound` = B sqrt(m d)
- `relation_rbin_prime_bound` = 8 m d w^2 p^2 phi_2 B sqrt(3 m d)
- `gamma_le` = 4 phi_3 m d B w p sqrt(||omega||_1^2 + S + 1)
- `completeness_error_protocol1/5` = 1 - 1/(product of mu's)

Each formula is unit-tested against hand-computed values (e.g. all-ones
gamma_bin = 4 sqrt(35); gamma_le = 4 sqrt(3)).

## pqct.parameter_validation

Composes the bounds with the core-SVP hardness estimator into one chain:

```text
Protocol parameters
  -> required HMC binding bound (gamma_bin / gamma_LE, Theorem 1/2)
  -> Theorem 1 q/2 precondition check
  -> binding bound as M-SIS beta into Gao Eq.(2)
  -> required root-Hermite factor delta -> BKZ blocksize -> core-SVP bits
```

Answers "do these parameters deliver the claimed security level?" for a
concrete parameter set.

## Two findings this produced (both important, both honest)

### 1. The lab's TOY fixtures FAIL Theorem 1's own precondition

`q=12289, w=4, phi1=1, p=2, k=5, d=8` gives q/2 = 6144.5 but the theorem
requires > 16*(4*1)^2*2*5*8 = 20480. So the soundness theorem DOES NOT
APPLY to the toy parameters used across the test suite. They exercise the
algebra correctly; they carry zero security meaning. Pinned by
`test_TOY_FIXTURE_FAILS_THE_PRECONDITION` so it cannot be silently
"fixed" into a false comfort.

### 2. Gao's reported profile lands ~89 classical bits under OUR estimator

With the paper's q=2^49-2^18+2^9+1, d=64, m=60, w=56, p=8, k=64, phi1=11:

```text
gamma_bin ~ 1.23e15  ->  required delta ~ 1.0048
                     ->  BKZ blocksize ~ 304
                     ->  ~89 classical / ~81 quantum core-SVP bits
```

This is BELOW 128 bits. It is NOT a claim that Gao's parameters are
insecure -- it is what OUR self-built cited-constants estimator (not the
verified lattice-estimator) produces from OUR reading of the binding
bound, ignoring dual/hybrid attacks and exact GSA slope that the real tool
models. The gap between this number and the paper's claimed 128-bit target
is exactly why blocker item 5 (a VERIFIED estimate via real Sage
lattice-estimator) remains open and matters. The chain is built so that
when the verified estimator is available, it slots in here unchanged.

## Boundary

These are bookkeeping formulas, not a proof that the implementation
satisfies them, and not a certified hardness estimate. Synthetic research
only; no production/testnet/mainnet use.
