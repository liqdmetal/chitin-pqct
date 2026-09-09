# Verified lattice estimate (blocker item 5) — status and findings

The real `malb/lattice-estimator` (Albrecht/Player/Scott) is installed and
runs in a sandboxed WSL user. Blocker item 5 is still OPEN, but for a
different reason than this document previously claimed — see the correction.

## Sandbox (how to run it)

Dedicated unprivileged user, no sudo, uid-scoped nftables:

```
wsl -u pqct -e bash -lc '~/miniforge3/envs/sage/bin/sage -python \
  /mnt/c/Users/officeone/pq-ct-research/tools/sage_sis_estimate.py [phi1]'
```

Verified sandbox properties:

```
pqct -> internet            HTTP 200   (allowed: needed for installs)
pqct -> LAN 192.168.4.73    BLOCKED    (protects desktop + redbox)
pqct -> sudo                DENIED
root / ryan1 / hermes       UNAFFECTED (rules are meta skuid != 1001 accept)
```

Toolchain: miniforge3 -> conda env `sage` -> `sage` 10.7 (conda-forge; note
`sagemath-standard` does NOT exist on conda-forge, the package is just `sage`)
-> `pip install git+https://github.com/malb/lattice-estimator`.

## CORRECTION: the earlier "trivially easy" finding was MY error

An earlier version of this document reported that the verified estimator
refused the paper profile with `SIS trivially easy. Please set norm bound < q.`
and framed that as a finding about the paper's parameters. It was not. Three
separate errors on my side produced it:

1. **Wrong bound.** I used the UNREDUCED Theorem 1 `gamma_bin`. The paper's own
   evaluation (Section 8) uses a REDUCED bound from [EZS+19], Eq.(21),
   `gamma_bin = max{B_Bin, B_Amor}`, obtained by additionally checking that
   `||(g_i*(x*1-g_i))_i||` is a factor 4d below the theoretical bound, trading
   completeness error (<1%) for a much smaller binding bound. Reduced:
   1.43e14 vs unreduced 2.29e15 — a factor ~16.
2. **Wrong phi.** I guessed `phi_1 = phi_2 = 11`. The paper states its
   evaluation setting explicitly (line ~1600): `phi_1 = phi_2 = 15`.
3. **Wrong norm.** I passed `norm=2` with a `sqrt(cols)` L2 inflation
   (~62.5x). Since `gamma_bin` is an L_inf (coefficientwise) bound, the
   natural reading is `norm=oo` with the bound passed directly and no
   inflation. The inflation was unnecessary and wrong.

   *Correction to a claim I made while fixing this:* I cited the estimator's
   built-in `Dilithium3_MSIS_WkUnf` constant as evidence for the `norm=oo`
   convention. That citation was never verified — enumerating `SIS` for
   `Dilithium*` attributes returned an EMPTY list in this install, so no such
   constant was available to cite. The `norm=oo` reasoning stands on the norm
   semantics alone (an L_inf bound is an L_inf bound), not on a docstring
   example. `SIS.Parameters` signature is
   `(n: int, q: int, length_bound: float, m: int = None, norm: int = 2, tag: str = None)`,
   i.e. **`norm` defaults to 2** and must be passed explicitly.

With all three corrected, `gamma_bin = 1.43e14 < q = 5.63e14`, so the instance
is well-posed and the paper's Eq.(2) argument goes through as published.

## Reproduced the paper's OWN published numbers

`tools/reproduce_paper_binding.py` (pinned by
`tests/test_paper_binding_reproduction.py`) recomputes Section 8's two printed
values from the transcribed formulas at the paper's evaluation profile:

```
                                  ours            paper prints
2*gamma_bin (Eq.21 reduced)       2.8636e14       ~2.86e14    MATCH
min{q, 2^(2 sqrt(n d log q log delta))}
                                  4.0999e14       ~4.10e14    MATCH
B_Amor < B_Bin  at S <= 2         True            claimed     MATCH
```

Reproducing a published numeric claim is a far stronger check on a
hand-transcribed formula than any self-consistency test: a wrong constant,
exponent or factor would miss these values. Formulas live in
`pqct/paper_bounds.py` as `gamma_bin_reduced` and `eq2_rhs` (single source;
the tool delegates to them).

A bug found and fixed while doing this: `eq2_rhs` originally computed
`2^(2*sqrt(n*d*d*log2(q)*log2(delta)))` — double-counting `d` by using
`n_module*d` and then multiplying by `d` again. That made the exponential term
exceed `q`, so the `min` silently collapsed to `q` (5.63e14) instead of the
paper's 4.10e14. The correct form uses `n*d` exactly once.

## What still blocks a certified bit number

The estimator itself does not yet run to completion in this environment. After
fixing the two call-site errors above, it fails inside Sage:

```
TypeError: Cannot convert gmpy2.mpz to sage.rings.integer.Integer
```

raised in `sage.libs.mpmath.utils.mpfr_from_mpfval`, i.e. the gmpy2 build in
this conda env is ABI-incompatible with Sage's mpfr conversion on the `erf`
path used by the sieving cost models. All cost models (ADPS16, BDGL16, MATZOV,
CheNgu12, GJ21, Kyber, LaaMosPol14, ABFKSW20, ABLR21, ChaLoy21) fail
identically. Diagnosis of two earlier-looking failures, both mine:
passing cost-model CLASSES instead of INSTANCES (which shifted `self`/`beta`
and produced a misleading `short_vectors() missing 1 required positional
argument: 'd'`), and passing native Python ints where Sage Integers are
required.

This is an environment/dependency problem, not a protocol or parameter
problem. It does not affect anything in `pqct/` (pure stdlib).

Attempted workaround that FAILED and should not be retried: removing gmpy2
from the env (`conda remove --force gmpy2`) so mpmath falls back to its float
path. gmpy2 is a hard Sage dependency, so this broke `import sage.all` entirely
(`sage.structure.coerce` -> ModuleNotFoundError). gmpy2 was restored. The
incompatibility is inside the conda build's gmpy2<->mpfr conversion and needs
either a matching gmpy2 ABI, a distro-packaged Sage, or running upstream's own
CI image — not more call-site tinkering.

## What is verified vs open

- VERIFIED: paper's reduced `gamma_bin` and Eq.(2) RHS reproduced to the
  printed digits; instance is well-posed (`gamma_bin < q`).
- VERIFIED: the toy fixtures fail Theorem 1's `q/2` precondition
  (see docs/PAPER_BOUNDS.md).
- VERIFIED: my self-built estimator lacked a `beta >= q` ill-posedness guard
  that the verified tool enforces; added and test-pinned. That guard remains
  correct and worth keeping — it catches genuinely infeasible parameter sets.
- OPEN: an actual bit-security figure from the verified tool (blocked on the
  Sage/gmpy2 environment issue). No certified number is claimed, and no
  128-bit claim is made anywhere.

## Boundary

Synthetic research only. No production, testnet, or mainnet use. The sandbox
exists to keep third-party toolchain installs off the LAN and away from
redbox, per the standing "never build third-party repos on prod boxes" rule.
