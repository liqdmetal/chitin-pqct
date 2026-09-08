# Experiment Log

## 2026-09-07 — Parameter lane separation and review

- Paper: Gao et al., IACR ePrint 2021/1674.
- Executable lane: toy parameters only; security claim = 0 bits.
- Paper-record lane: `d=64, w=56, p=8, q=2^49-2^18+2^9+1, n=29, m=60, k=64, S=1`.
- The paper reports a 128-bit post-quantum target for its complete construction and small-output binary proofs. This was recorded as provenance, not independently accepted.
- Added `pqct/parameters.py` with explicit `GaoPaperProfile` and `ToyProfile` validation.
- Added `docs/INDEPENDENT_REVIEW.md` with initial severity-ranked findings.
- Added `docs/EXPERIMENT_PROTOCOL.md` with launch lanes, stop conditions, and required mutation families.
- Full test suite: 48 tests passed.
- Python compilation: passed.
- DERO checkout: existing untracked files present; no changes made by this experiment.

### Findings carried forward

1. The toy challenge is scalar and bounded; the paper challenge is ring-valued and sparse.
2. Exact `D1/D2/D3` distributions and rejection calibration are not implemented.
3. No concrete Module-SIS/M-LWE estimator output has been independently produced.
4. The binary transcript is Protocol-1-shaped but not a security-equivalent implementation.
5. A second independent implementation is still required.
