# M-SIS hardness: the delta criterion, and how a false alarm was resolved

Module: `pqct/msis_hardness.py`. Tests: `tests/test_msis_hardness.py` (18).
Gate: `tools/stack_check.py` step 4.

## The contradiction

Three methods gave three answers for the same paper profile
(phi1=phi2=15, B=1, (d,w,p)=(64,56,8), q=2^49-2^18+2^9+1, (n,m)=(29,60),
k=64, S=2, gamma_bin = 1.4318e14 reduced via Eq.21):

| method | verdict |
|---|---|
| real lattice-estimator (scalar bound) | 83-113 bits |
| my Gaussian-heuristic gate | "trivially easy", i.e. ~0 bits |
| the paper (Section 8) | "suffices the 128-bit security" |

## Resolution: my gate was wrong, and it was the wrong dimension

The gate evaluated the Gaussian heuristic at the FULL column count
(m_int = (m+v)*d = 7936), got gamma/GH ~ 5e10, and concluded the instance
was trivially easy. That reasoning is invalid: **an attacker is not confined
to the full-column lattice, they drop columns.** Hardness is governed by the
best sub-dimension, not the largest one.

Gao's Eq.(2) already encodes this. Its exponential term

```
2^( 2*sqrt(n*d*log2(q)*log2(delta)) )
```

is exactly the minimum over m' of `delta^m' * q^(n*d/m')`, attained at

```
m' = sqrt( n*d*log2(q) / log2(delta) )
```

For this profile m' ~ 3787. `tests/test_msis_hardness.py` verifies both
claims numerically: that m' minimises the length (checked against m' scaled
by 0.5x-2.0x) and that the value at m' equals Eq.(2)'s exponential.

Independent corroboration: the real lattice-estimator reported working
dimensions `d` in **3378-4008** for this instance, bracketing the analytic
m' ~ 3787. Two unrelated code paths agree that ~3800, not 7936, is the
operative dimension.

"Short vectors exist" (counting) is not "short vectors are cheap to find"
(cost). Conflating them produced the false alarm. The gate in
`tools/sage_sis_estimate.py` has been corrected to report the counting
statement without issuing a hardness verdict.

## What the criterion actually says

Measured for beta = 2*gamma_bin (two openings each within gamma differ by at
most 2*gamma, so this is the M-SIS norm an HMC binding-breaker must reach):

```
beta = 2*gamma_bin        = 2^48.02 = 2.8636e14
q                         = 2^49.00
beta < q                                          -> True
Eq.(2) RHS at delta=1.0045 = 2^48.54
Eq.(2) HOLDS                                      -> True   (margin 2^0.52, ~1.4x)
attacker needs delta       = 1.0044043
  -> BKZ block size k      = 345
  -> optimal sub-dimension  = 3787
```

**Eq.(2) holds, so the paper's own criterion is satisfied** -- but with a
margin of only ~1.4x in the norm. That is tight; a small parameter change
could flip it, which is why the stack check pins it.

Cross-check on delta: the estimator reported `delta = 1.0042178`, the Eq.(2)
inversion here needs `1.0044043`. Agreement to ~3e-4 from two independent
implementations.

## Where the "128-bit" claim comes from, and why modern models disagree

Converting delta to bits is a **model choice**, not arithmetic. At k = 345:

| cost model | bits |
|---|---|
| ADPS16 quantum (0.265k) | 91.5 |
| ADPS16 classical (0.292k) | 100.9 |
| MATZOV22 quantum | 116.2 |
| BDGL16 classical | 117.3 |
| legacy delta=1.0045 <-> "128-bit" (MatRiCT) | 128 by assumption |

The paper inherits the delta=1.0045 <-> 128-bit correspondence from MatRiCT
[EZS+19]. Under modern core-SVP models the same delta is worth ~92-117 bits.
So the gap between "128-bit" and our 92-117 is **not an arithmetic error in
the paper**; it is the legacy delta->bits mapping. Both numbers describe the
same lattice problem.

The BKZ root-Hermite formula used here is pinned against published anchors
(delta 1.005 <-> k~286, 1.0045 <-> k~335, 1.003 <-> k~596) and round-trips
to 12 decimal places.

## Still open (this document certifies nothing)

1. **The exact M-SIS instance.** HMC binding gives a collision
   `z = (dm, dr)` with MIXED per-column bounds: `dm` small on the v message
   columns, `dr` small on the m randomness columns. A single scalar
   `length_bound` cannot express that, so both the estimator run and the
   delta criterion above use a uniform-bound approximation. Whether the
   mixed structure makes the real instance harder or easier than this
   approximation is a question for a lattice cryptographer.
2. **delta -> bits.** Which cost model to adopt is a judgement call about
   sieving costs, memory access, and quantum speedups.
3. **The margin is 1.4x.** Eq.(2) holds, but not comfortably.

No certified bit-security level is claimed anywhere in this repository. What
IS established: the paper's criterion is satisfied for its stated profile,
two independent methods agree on delta, and the earlier "trivially easy"
verdict was a false alarm of mine.
