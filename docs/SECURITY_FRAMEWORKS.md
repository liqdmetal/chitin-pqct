# Security frameworks: Fiat-Shamir and end-to-end bit security

Modules: `pqct/fiat_shamir_framework.py`, `pqct/security_budget.py`.
Tests: `tests/test_fiat_shamir_framework.py` (18), `tests/test_security_budget.py` (17).
Gate: `tools/stack_check.py` step 6.

**These are frameworks, not proofs.** No Fiat-Shamir security proof and no
certified bit-security level exists in this repository. What follows is the
ledger a real claim would have to balance, made executable so the gaps are
precise rather than rhetorical.

## Finding 1: the optimistic Fiat-Shamir margin is ~0 bits at Q = 2^64

| term | bits |
|---|---|
| challenge-space soundness, `\|C_{w,p}\| = C(64,56)*16^56` | +256.0 |
| classical forking loss, `(t-1)*log2(Q)` with t=3 | -128.0 |
| QROM adaptive-reprogramming loss, `2*log2(Q)` | -128.0 |
| **residual (OPTIMISTIC)** | **+0.04** |

Sensitivity:

```
Q       soundness  forking  qrom   residual
2^32       256.0     64.0    64.0    +128.0
2^48       256.0     96.0    96.0     +64.0
2^64       256.0    128.0   128.0      +0.0
2^80       256.0    160.0   160.0     -64.0
2^96       256.0    192.0   192.0    -128.0
```

Two things follow. First, the margin is driven by the **query budget**, and
goes negative for Q >= 2^80. Second, the cost is dominated by needing THREE
transcripts: forking loss is `(t-1)*log2(Q)`, so a 2-transcript extractor
would recover 64 bits. That is a concrete design lever, not a vague concern.

`residual_bits_optimistic` is named "optimistic" because it presumes every
open obligation is discharged at no additional loss -- which is exactly what
has not been shown. It is not a security level.

## The eight Fiat-Shamir obligations

| obligation | status |
|---|---|
| special soundness from 3 transcripts | **code-evidenced** (`three_transcript_extraction.py`) |
| challenge-space size | **computed** (exact combinatorics) |
| statement binding | **code-evidenced** (`tx_envelope.py`, 4 subtests) |
| QROM reprogramming loss | **computed** (bookkeeping only) |
| commitment binding under relaxation | open |
| classical rewinding to 3 transcripts | open |
| quantum rewinding obstruction | **not attempted** |
| transcript simulation / SHVZK | open |

The distinction that matters: we have an extractor that works *given* three
accepting transcripts. Fiat-Shamir needs those transcripts *produced* from a
single non-interactive prover. Classically that is rewinding; quantumly the
classical argument does not transfer, because measuring a superposition
query collapses the adversary's state. Instantiating a
measure-and-reprogram argument (Don-Fehr-Majenz-Schaffner;
Grilo-Hovelmanns-Hulsing-Majenz) for this protocol's round structure is
research-paper-scale and is not attempted.

## Finding 2: M-LWE hiding was never analysed

The budget surfaced a gap nothing else tracked. Security is a minimum over
independent assumptions, minus losses:

| component | bits | certification |
|---|---|---|
| M-SIS binding | 91.5-117.3 | two methods agree (delta to ~3e-4) |
| **M-LWE hiding** | **93.5-119.4** | **dual-attack delta criterion** |
| ML-DSA-65 signature | 192 | external (NIST FIPS 204 cat. 3) |
| challenge soundness | 256 | computed exactly |

**M-LWE hiding is now analysed** (`pqct/mlwe_hardness.py`, 19 tests). Gao
Lemma 1 requires `M-LWE(m-n, m, q, B)` = M-LWE(31, 60, q, 1) hard for the
HMC to be computationally hiding -- that is what keeps committed amounts
confidential, and nothing in this repository had estimated it.

Section 8 (line ~1662) applies the SAME delta ~ 1.0045 Eq.(2) criterion to
M-LWE as to M-SIS, so the analysis is directly comparable rather than a
separate methodology. Via the dual attack: the dual lattice has dimension m'
and volume q^N, so BKZ reaches `delta^m' * q^(N/m')`, minimised at the same
sqrt form, and the attack succeeds once that falls below `q/sigma_e`. That
is Eq.(2) with `beta := q/sigma_e`, so `pqct.msis_hardness` is reused rather
than reimplemented.

Result: **93.5-119.4 bits**, criterion holds, delta = 1.0043404, BKZ k = 353.

Two findings worth stating:

* **It lands within ~2 bits of M-SIS** (91.5-117.3), independently
  confirming the paper's `m ~ 2n` balancing claim. A test pins the two
  within 10 bits, so a future parameter change that unbalances them fails
  the suite.
* **The instance is SAMPLE-LIMITED.** The optimal dual dimension wants ~3944
  columns but the HMC exposes only 3840, so the attacker is forced
  off-optimum and the true instance is HARDER than the unconstrained formula
  gives. Reporting the unconstrained number would understate security --
  safe direction, still wrong, so both are computed and the binding regime
  is stated.

Caveats: delta -> bits remains a model choice, and ternary secrets (B=1) may
admit hybrid/combinatorial attacks that beat this generic dual-attack
estimate. Not modelled. M-LWE moved from "unanalysed" to "analysed,
uncertified".

Note the treatment of "unknown" vs "known weak": the unanalysed term is not
folded into the minimum as 0 bits (which would be misleading arithmetic).
It blocks the CLAIM instead. `test_still_not_claimable_even_if_residual_were_positive`
pins that behaviour, so a comfortable residual can never unlock a claim
while a component is unanalysed.

## Verdict

```
capped by       : M-SIS binding
min (certified) : 91.5-117.3 bits
total loss      : 256.0 bits
residual        : -164.5 to -138.7 bits
claimable       : False

NO CLAIM: unestablished loss(es): forking/rewinding, QROM reprogramming;
          residual is non-positive (-164.5 bits)
```

All four components are now certified (uncertified = 0), so the remaining
blockers are the two unestablished LOSSES and the negative residual. A claim
becomes possible only when every component is certified, every loss is
established, AND the residual is positive -- and even then the verdict says
"still requires external review".

## The 64-bit forking saving: asked and ANSWERED (no)

`pqct/two_transcript_extraction.py` (16 tests) settles whether dropping to
t=2 transcripts is free. It is not.

Two transcripts DO recover both relaxed values -- the system

```
g0 = x0*b + t
g1 = x1*b + t
```

is exactly determined, giving `y*b = g0-g1` and `-y*t = x1*g0-x0*g1`. But
"exactly determined" is the problem: **any** response pair is consistent
with some `(b,t)`, because you solve the 2x2 system and always get an
answer. There is no residual equation left to falsify.

`verify_two_transcript_consistency` is therefore a TAUTOLOGY, and is written
and tested as one -- a test feeds it arbitrary responses `(3,5)`, `(11,2)`,
`(0,7)`, `(100,250)` and asserts it still "passes", because a check that can
never fail is not a check.

The decisive test constructs a prover whose third response breaks affineness:

* all three PAIRS pass two-transcript consistency
* the TRIPLE fails `(x1-x2)(g0-g1) == (x0-x1)(g1-g2)`

So dropping to t=2 does not merely lose redundancy, it removes the only
transcript-level test of the binary relation. The 64 bits could still be
recovered if the binary relation turns out to be enforced by the
per-transcript E/F commitment equations alone -- `binary_relation_source()`
records that as **UNRESOLVED**, with both branches stated, rather than
letting the saving be assumed.

## Mixed-bound M-SIS: bracketed, not resolved

`pqct/mixed_bound_msis.py` (16 tests). The real HMC-binding instance has
per-block bounds a single scalar cannot express:

| block | columns | bound | why |
|---|---|---|---|
| message `dm` | 4096 | 1 | bit commitments, so `dm` in {-1,0,1} |
| randomness `dr` | 3840 | 2 | `r` from {-B..B} with B=1, so \|dr\| <= 2B |

The two uniform extremes bracket it:

* **bound = 2** (uniform-tight): needs delta = 1.0000019, **unreachable by
  any bounded BKZ block size** -- off-scale hard, no finite bit figure
  applies. This overstates security.
* **bound = 2*gamma_bin = 2.86e14** (uniform-relaxed): 92-117 bits. This
  understates security, because the randomness block is really tiny.

The counting slack for the true mixed box is **-75,536 bits**
(`sum_j log2(2b_j+1) - n*d*log2(q)`), i.e. the box is nowhere near large
enough to guarantee a solution. That is evidence the 92-117 figure is a
conservative FLOOR rather than an overstatement -- useful, and the direction
that matters.

Deliberately, slack is reported as `slack_bits_counting` and is **never
converted into bits of security**; a test asserts no `slack_bits_security`
key exists. Conflating a counting statement with a cost statement is exactly
what produced the earlier false "trivially easy" alarm.

Volume-equivalent scalar (the most defensible single substitute): **1.42**.

Still OPEN: narrowing the interval needs an estimator that accepts per-block
bounds (lattice-estimator does not) or a hand analysis by a lattice
cryptographer.

## What would move these numbers

1. ~~Analyse M-LWE hiding.~~ **DONE** (93.5-119.4 bits, balanced with M-SIS).
2. ~~A 2-transcript extractor, worth 64 bits.~~ **ANSWERED: not free.** The
   only transcript-level test of the binary relation lives in the third
   transcript. Recoverable only if the relation is enforced per-transcript
   by the E/F equations -- unresolved.
3. **Establish the two losses.** This is now the binding constraint: the
   forking and QROM losses are bookkeeping, not applied theorems. Until a
   measure-and-reprogram argument is instantiated for this protocol's round
   structure, the -256 bit total stands and the residual stays negative.
4. **Narrow the mixed-bound interval.** Bracketed between "off-scale hard"
   and 92-117 bits, with counting slack -75,536 suggesting the low end is a
   conservative floor. Needs per-block estimator support or hand analysis.
5. **Larger parameters.** 256 bits of soundness is generous; the binding
   term (92-117) is the cap, so raising n or d lifts the minimum but does
   nothing about the losses -- which now dominate.

Item 3 is the one that matters. Items 3 and 4 both need a lattice/ZK
cryptographer; nothing further is tractable here without one.
