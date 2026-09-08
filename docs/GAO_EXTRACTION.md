# Gao et al. Balance Proof Extraction — Working Notes

**Source:** Gao et al., “Lattice-based Zero-knowledge Proofs for Blockchain Confidential Transactions,” IACR ePrint 2021/1674; source text and implementation link checked 2026-09-07.

**Status:** equation extraction only. This is not an implementation or a security endorsement.

## 1. Core relation

The paper defines a public linear function:

```text
F(X_0, ..., X_{S-1}) = Σ_i ω_i X_i
```

The prover must show knowledge of bounded binary vectors `b_i ∈ {0,1}^k` and commitment openings such that:

```text
B_i = Com_ck(b_i, r_{b_i})
F'(b_0, ..., b_{S-1}) = 0
```

where:

```text
F'(b_0, ..., b_{S-1}) = Σ_i ω_i · <2^k, b_i>
```

The verifier derives the bitwise linear-combination vector:

```text
c_j = Σ_i ω_i b_{i,j}
```

and therefore the balance condition is:

```text
<2^k, c> = Σ_j 2^j c_j = 0
```

For a transfer-style balance equation, the coefficient vector is positive for outputs and negative for inputs. Fees, issuance, and burns must be modeled explicitly rather than silently folded into a zero-sum equation.

## 2. Commitment linearity

The verifier computes the commitment to `c` from the public bit commitments:

```text
C = Σ_i ω_i B_i
```

The prover samples a masking vector `d` and forms:

```text
f = x·c + d
```

where `x` is the Fiat–Shamir/challenge value. Linearity gives:

```text
Com_k(f; *) = x·C + D
```

The protocol must additionally establish that the weighted sum of `f` is zero without allowing modular wraparound to turn a nonzero integer relation into a zero relation in the ring.

## 3. The overflow issue

Checking the weighted sum only in `R_q` is insufficient when `q` is too small:

```text
< f, 2^k > mod q = 0
```

does not necessarily imply:

```text
< c, 2^k > = 0
```

over the intended integers. The paper addresses this with **cycle masking**, selecting the mask so the weighted mask sum is zero while keeping response coefficients short. This is a central security/correctness condition, not an optimization that can be omitted.

## 4. Protocol 2 transcript boundary

The extracted protocol flow is:

1. Run the partially amortized binary proof to obtain initial commitments `E, F, G`.
2. Set a norm bound based on the positive/negative coefficient weights.
3. Compute the bitwise relation vector `c`.
4. Sample the masked-vector randomness and a commitment randomness for `D`.
5. Derive the cycle-masked `d` values.
6. Commit to the mask, producing `D`.
7. Verifier receives `D, E, F, G`.
8. Derive challenge `x` from the derived commitment `C`.
9. Run the binary proof response phase using `x`.
10. Form the response vector `f` and omit one coordinate because the weighted sum is constrained.
11. Apply rejection sampling to the response vector and commitment opening response.
12. Return the response transcript.
13. Verifier reconstructs the omitted coordinate over the integer/ring boundary required by the paper.
14. Verifier checks response norms, the commitment equation, and the binary-proof verifier.

The source extraction has notation corruption in the HTML/text conversion around several indices. The PDF and reference implementation must be used to resolve every subscript before coding.

## 5. RingCT specialization

For `M` inputs and `S` outputs, the paper specializes the linear equation to:

```text
F(a_0, ..., a_{M-1}, b_0, ..., b_{S-1})
  = Σ_{i=0}^{S-1} b_i - Σ_{i=0}^{M-1} a_i
```

That specialization is useful algebraically, but it is **not yet the DERO account statement**. Our first account-mode version should substitute:

```text
old_balance + credits - new_balance - debits - fee = 0
```

with each term bound to a versioned account-state commitment and transaction context.

## 6. Parameters found in the paper’s evaluation

The evaluation reports example settings including:

```text
φ1 = φ2 = 15
B = 1
(d, w, p) = (64, 56, 8)
q = 2^33 - 2^18 + 2^2 + 1
(n, m) = (20, 60)
```

It reports a 64-bit amount setting (`k = 64`) and output count `S = 1` in its balance-proof comparison.

**Do not use these as production parameters.** The paper’s evaluation settings are tied to its complete construction, security analysis, distributions, ring representation, proof components, and implementation. They are not validated for our account-mode adaptation.

## 7. Immediate blockers before implementation

- Recover clean notation from the PDF, not the text extractor.
- Resolve the apparent OCR/HTML errors in the cycle-masking equations.
- Extract the exact partially amortized binary protocol dependency.
- Identify the exact commitment construction `Com_ck` and its dimensions/distributions.
- Reproduce the rejection-sampling distributions and acceptance bounds.
- Map the proof’s ring operations to a standalone reference model.
- Write negative tests for modular-wraparound forgeries, altered challenge, altered commitments, malformed norms, and non-binary witnesses.
- Keep all work outside `derohe`.

## 8. Explicit conclusion

Gao’s linear-equation proof is a promising **balance-proof component**. It is not, by itself:

- an encrypted account balance;
- an authorization signature;
- a complete account-transition proof;
- a double-spend solution;
- a DERO consensus integration;
- a production parameter set.
