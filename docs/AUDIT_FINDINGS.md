# Internal Audit Findings — Current State

**Decision:** NO-GO for production; GO for isolated synthetic research only.
**Supersedes:** the original 9-finding snapshot in this file. Historical
findings remain useful as provenance but must not be read as current status.

## Current verified evidence

- Ring-valued Protocol 1 path, canonical encoding, challenge ordering, sampled
  rejection harness, extraction laboratories, authorization/provenance layer,
  and synthetic value-node tests exist.
- AFK'22 classical and DFM'20 QROM accounting is implemented as a
  conditional framework. DFM's generic bound may be tight in its theorem
  model, but applicability to Chitin's full ring protocol and special-
  soundness argument remains pending external review.
- Three-transcript special-soundness experiments, relaxation accounting,
  quantum-rewinding scope checks, and a computed SHVZK bound exist; these are
  executable evidence and proof sketches, not a formal reduction.
- The sampler ships the 13-sigma tail and the budget reads that live setting.
- Current stack gate: 649 tests passed, all 7 stack steps green at the last
  verified run.

## Current blockers — still binding

### F-001 — Research parameters are not deployment parameters

Toy ring dimensions and estimator outputs do not establish a concrete
Module-SIS/Module-LWE security level. No 128-bit PQ or production claim is
permitted.

### F-002 — Paper-faithful distribution theorem remains external

The finite-support Gaussian and rejection implementation has a computed bound
and diagnostics, but Gao's exact distribution convention, smoothing conditions,
and Lemma 6 constant have not been independently re-derived.

### F-003 — Security reductions remain conditional

The extractor and verifier equations are executable and adversarially tested,
but a complete independently reviewed knowledge-soundness reduction for the
full ring implementation and all `S <= 2` composition is not established.

### F-004 — Concrete mixed-bound lattice estimates remain model-dependent

M-SIS/M-LWE numbers are estimator/model reports. Mixed bounds, ring embeddings,
hybrid attacks, multi-instance effects, and implementation assumptions require
expert review.

### F-005 — No independent second implementation

There is no independent Rust/C/Sage end-to-end implementation agreeing on full
transcripts and wire vectors.

### F-006 — Systems security is absent

No constant-time, side-channel, memory-safety, parser-fuzzing, wallet-recovery,
production key lifecycle, or deployment audit exists.

### F-007 — No external cryptanalysis or university review

Internal tests and delegated review do not substitute for independent
cryptanalysis.

## Verdict

The repository is a reproducible research artifact. It is not a secure proof
system, wallet, ledger, consensus component, or production cryptographic
implementation. Keep `NO CLAIM` until the blockers above are resolved by
independent work and external review.
