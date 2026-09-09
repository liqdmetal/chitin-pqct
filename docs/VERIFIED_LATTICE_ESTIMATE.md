# Verified lattice estimate (blocker item 5) — status and findings

The real `malb/lattice-estimator` (Albrecht/Player/Scott) is now installed
and runnable, inside a sandboxed WSL user. This closes the *tooling* half of
blocker item 5. It does NOT yet produce a certified security number, for a
substantive reason recorded below.

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

Toolchain: miniforge3 -> conda env `sage` -> `sage` 10.7 (conda-forge;
note `sagemath-standard` does NOT exist on conda-forge, the package is just
`sage`) -> `pip install git+https://github.com/malb/lattice-estimator`.
Cost models used: classical ADPS16/BDGL16, quantum MATZOV.

## Finding 1: the verified tool REFUSED inputs my self-built estimator accepted

My `pqct/lattice_estimate.py` (self-built, cited-constants) returned a
plausible-looking "~89 classical bits" for the paper profile. The verified
estimator rejected the same input outright:

```
SIS trivially easy. Please set norm bound < q.
```

Cause: Gao Eq.(2) is `min{q, 2^(...)} > beta`. If `beta >= q` the left side
is at most q, so the condition can never hold for any delta — the instance is
trivially easy and no bit figure is meaningful. For the paper profile at
phi1=11, gamma_bin = 1.23e15 > q = 5.63e14.

My estimator lacked that guard. **Fixed**: `estimate_sis_hardness` now raises
`LatticeEstimateError("... trivially easy ...")` when `beta_bound >= q`,
matching the verified tool's behaviour. Pinned by
`test_gamma_bin_above_q_refuses_hardness`. This is the concrete payoff of
getting the real tool: it caught a false-comfort path in my own code.

## Finding 2: the norm mapping is unresolved, and it dominates the answer

To feed a ring relation to an integer SIS estimator I must convert the
relation's norm bound into an L2 bound on a solution vector. I used the
conservative worst case (every one of `cols = (m+v)*d = 3904` integer
coefficients saturating the inf-norm bound), giving `l2 = sqrt(cols) *
gamma_bin` — a factor ~62.5 inflation.

Sweep result (paper profile, phi2=11):

```
phi1   gamma_bin        gamma_bin<q   l2_bound<q   estimator verdict
 11    1.23e15          NO            NO           trivially easy
  7    4.99e14          YES           NO           trivially easy
```

So even where gamma_bin itself is below q, my conservative L2 conversion
pushes the instance back over the line. The estimate is therefore dominated
by MY MAPPING CHOICE, not by the paper's parameters. Reporting any bit
number from it would be reporting my own assumption.

This is exactly the interpretation that needs a lattice cryptographer:
what norm, in which space, does the extracted relaxed opening actually
satisfy, and what is the correct L2 bound for the SIS instance the binding
reduction produces? Until that is answered, blocker item 5 stays open.

Also computed for reference: `max_phi1_with_gamma_bin_lt_q = 7.4358` (the
crossover where gamma_bin alone stays under q).

## What is verified vs open

- VERIFIED: the real estimator is installed and runs in a sandbox.
- VERIFIED: my self-built estimator had a missing ill-posedness guard; fixed
  and test-pinned.
- VERIFIED: the toy fixtures fail Theorem 1's q/2 precondition (see
  docs/PAPER_BOUNDS.md).
- OPEN: the ring-relation -> integer-SIS norm mapping. No certified bit
  number is claimed. No 128-bit claim is made anywhere.

## Boundary

Synthetic research only. No production, testnet, or mainnet use. The sandbox
exists to keep third-party toolchain installs off the LAN and away from
redbox, per the standing "never build third-party repos on prod boxes" rule.
