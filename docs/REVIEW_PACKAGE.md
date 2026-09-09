# Chitin Review Package

**Status:** research-only, no deployment, no wallet keys, no real balances,
no DERO integration, no consensus changes.

## Current verified state

- Repository: `https://github.com/liqdmetal/chitin-pqct` (private).
- Current local worktree must be checked before relying on this document.
- The executable Fiat–Shamir ledger has eight obligations. The current code
  marks them code-evidenced or computed, but that is **not a cryptographic
  proof** and does not justify a security claim.
- The project verdict remains `NO CLAIM`.
- The conservative two-round QROM residual is negative at the configured
  query budget; the statement-bound one-round variant is a research branch,
  not a production protocol.
- The toy ring, enumerated adversaries, estimator models, and cited Gao
  rejection constant do not transfer automatically to a concrete deployment.

## What is implemented evidence versus proof

| Area | Current evidence | Not established |
|---|---|---|
| Protocol 1 arithmetic | ring-valued reference path, canonical encoding, mutation tests | paper-complete security reduction |
| special soundness | executable three-transcript extractor and adversarial fixtures | a published, independently reviewed reduction for the full implementation |
| Fiat–Shamir/QROM | AFK'22/DFM'20 accounting wired into a framework | independent cryptanalytic confirmation that every theorem hypothesis transfers |
| SHVZK | finite-support bound and shipped 13-sigma sampler default | exact Gao distribution theorem and independently derived Lemma 6 constant |
| M-SIS/M-LWE | bounded estimator/model reports | certified concrete security, mixed-bound estimator, hybrid attacks |
| authorization/state | ML-DSA provenance and replay/double-spend toy node | production key lifecycle, recovery, side-channel and systems security |
| transaction composition | synthetic value-flow tests | confidential wallet/account semantics and deployment safety |

## Reproduce

From a clean checkout, use the repository's pinned Python environment and run:

```text
python -m pytest tests/ -q
python tools/stack_check.py
```

The stack check is an honesty gate: it rejects prohibited security language,
requires the paper-number reproduction, runs the synthetic testnet, and
requires the final verdict to remain non-claimable.

## Questions for an external cryptographer

1. Does the exact Gao Protocol 1 transcript satisfy the cited multi-round
   Fiat–Shamir theorem hypotheses after canonical encoding and rejection?
2. Does the relaxed-opening extractor yield the required Module-SIS instance
   with the stated mixed bounds, including all ring embeddings?
3. Are the finite-support sampler and rejection wrapper statistically close
   to the paper's exact distributions at the shipped tail?
4. Is the M-LWE hiding estimate valid for the actual ternary secret/error
   distributions, or do hybrid/combinatorial attacks dominate?
5. Does the statement-bound one-round zeta variant preserve the paper's
   completeness, soundness, and simulation arguments?
6. Which concrete parameter set, if any, survives independent estimation at a
   defensible post-quantum security target?

## Exit gate

Do not call Chitin secure, production-ready, quantum-proof, or 128-bit PQ.
No production/testnet integration is approved until an independent
implementation and external cryptographic review resolve the listed questions.
