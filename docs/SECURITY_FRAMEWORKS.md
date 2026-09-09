# Security frameworks: current executable ledger

Modules: `pqct/fiat_shamir_framework.py`, `pqct/security_budget.py`.
Gate: `tools/stack_check.py`.

**These are frameworks, not proofs.** The executable ledger tracks eight named
obligations with code evidence or computed bookkeeping where available. The
full special-soundness reduction and transfer of the DFM theorem hypotheses to
Chitin's ring protocol remain externally unverified; no certified Fiat–Shamir
security proof or concrete bit-security level exists.

## Current verified ledger

| term | current treatment |
|---|---|
| challenge-space soundness | 256-bit toy challenge-space scale |
| classical AFK'22 loss | 64 bits at `Q=2^64`, conditional on the interactive extractor |
| DFM'20 QROM loss beyond classical | 195 bits at `Q=2^64` under the theorem's hypotheses; generic bound is tight in its model, but transfer to Chitin remains externally unverified |
| SHVZK finite-support/truncation | computed from the shipped 13-sigma tail; exact Gao distribution theorem remains external |
| M-SIS | model-dependent ~92–117-bit range in current estimator interpretation |
| M-LWE | model-dependent ~94–119-bit range; no certified claim |
| final verdict | **NO CLAIM**, residual negative under the configured two-round ledger |

## Why the zero-open status is not a security claim

The eight obligations are executable evidence gates, not a theorem prover. The
remaining boundary is external: paper-faithful distributions, complete
reduction transfer, ring/mixed-bound lattice analysis, independent
implementation, side-channel/system review, and university-level cryptanalysis.

The statement-bound one-round zeta branch has a materially better generic QROM
ledger, but it is a research variant and is not a deployment recommendation.

## Reproduce

```text
cd C:/Users/officeone/pq-ct-research
python -m pytest tests/ -q
python tools/stack_check.py
```

The claim audit must continue to reject `secure`, `production-ready`,
`quantum-proof`, and `128-bit PQ` claims. No production, testnet, wallet-key,
real-balance, DERO-integration, or consensus use is approved.
