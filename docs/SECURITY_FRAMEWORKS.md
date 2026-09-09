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
| **M-LWE hiding** | **-** | **UNANALYSED** |
| ML-DSA-65 signature | 192 | external (NIST FIPS 204 cat. 3) |
| challenge soundness | 256 | computed exactly |

Gao Lemma 1 requires `M-LWE(m-n, m, q, B)` hard for the HMC to be
computationally **hiding** -- that is what keeps committed amounts
confidential. No estimate for it exists anywhere in this repository. It is
as serious as the binding gap and had not been named before now.

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

NO CLAIM: uncertified component(s): M-LWE hiding;
          unestablished loss(es): forking/rewinding, QROM reprogramming;
          residual is non-positive (-164.5 bits)
```

A claim becomes possible only when every component is certified, every loss
is established, AND the residual is positive -- and even then the verdict
says "still requires external review".

## What would move these numbers

1. **Analyse M-LWE hiding.** Currently absent; the same estimator and
   delta-criterion machinery applies.
2. **A 2-transcript extractor**, if the relation permits one, worth 64 bits
   of forking loss at Q = 2^64.
3. **A tighter QROM result** than the conservative `2*log2(Q)`, which
   requires first settling which theorem applies.
4. **Larger parameters.** 256 bits of soundness is generous; the binding
   term (92-117) is the cap, so raising n or d helps the minimum but not
   the losses.
5. **The mixed-bound M-SIS instance.** HMC binding gives a collision with
   small `dr` on randomness columns and small `dm` on message columns; a
   single scalar norm cannot express it, so the 92-117 range is an
   approximation in both directions.

Items 1 and 2 are tractable here. Items 3 and 5 need a lattice
cryptographer.
