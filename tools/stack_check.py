"""Full-stack gate: run this after every change. One command, honest verdict.

    python tools/stack_check.py

Runs, in order, and reports a single PASS/FAIL:

  1. pytest            -- the whole unit/adversarial suite
  2. compileall        -- syntax across pqct/, tests/, tools/
  3. paper reproduction-- Gao's printed 2*gamma_bin and Eq.(2) RHS
  4. M-SIS criterion   -- Eq.(2) holds; delta agrees with lattice-estimator
  5. testnet           -- mine blocks, run attacks, require 0 successes
  6. claim audit       -- grep the tree for forbidden security claims

Step 6 exists because the most dangerous regression in this repo is not a
broken test, it is a sentence: any drift toward "secure", "128-bit", or
"production-ready" is a bigger problem than a failing assert.

The sandboxed Sage estimator is NOT run here (it needs WSL and ~1 min);
run tools/sage_sis_estimate.py under `wsl -u pqct` separately.
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PY = sys.executable


class Step:
    def __init__(self, name: str):
        self.name = name
        self.ok = False
        self.detail = ""
        self.seconds = 0.0


def run(cmd: list[str], timeout: int = 900) -> tuple[int, str]:
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {time.perf_counter()-started:.0f}s"


def step_pytest(step: Step) -> None:
    code, out = run([PY, "-m", "pytest", "-q"])
    match = re.search(r"(\d+) passed", out)
    count = match.group(1) if match else "?"
    failed = re.search(r"(\d+) failed", out)
    step.ok = code == 0 and not failed
    step.detail = f"{count} passed" + (f", {failed.group(1)} FAILED" if failed else "")


def step_compile(step: Step) -> None:
    code, out = run([PY, "-m", "compileall", "-q", "pqct", "tests", "tools"])
    step.ok = code == 0
    step.detail = "clean" if code == 0 else out.strip().splitlines()[-1][:120]


def step_paper_reproduction(step: Step) -> None:
    """Gao's published numbers must still reproduce to the printed digits."""
    from pqct.paper_bounds import eq2_rhs, gamma_bin_reduced

    gb = gamma_bin_reduced(8, 64, 56, 64, 2, Decimal(15), Decimal(15), 1, 60)
    two_gb = float(2 * gb)
    rhs = float(eq2_rhs(29, 64, 2 ** 49 - 2 ** 18 + 2 ** 9 + 1, Decimal("1.0045")))
    ok_gb = abs(two_gb - 2.86e14) / 2.86e14 < 0.01
    ok_rhs = abs(rhs - 4.10e14) / 4.10e14 < 0.02
    step.ok = ok_gb and ok_rhs
    step.detail = (
        f"2*gamma_bin={two_gb:.3e} (paper 2.86e14) {'OK' if ok_gb else 'DRIFT'}; "
        f"Eq2 RHS={rhs:.3e} (paper 4.10e14) {'OK' if ok_rhs else 'DRIFT'}"
    )


def step_msis_criterion(step: Step) -> None:
    """Eq.(2) must hold, and our delta must match lattice-estimator's."""
    from pqct.msis_hardness import analyze_msis
    from pqct.paper_bounds import gamma_bin_reduced

    gb = gamma_bin_reduced(8, 64, 56, 64, 2, Decimal(15), Decimal(15), 1, 60)
    report = analyze_msis(
        n_module=29, d=64, q=2 ** 49 - 2 ** 18 + 2 ** 9 + 1, beta=float(2 * gb)
    )
    estimator_delta = 1.0042178225657392  # measured by the real tool
    agrees = abs(report.required_delta - estimator_delta) < 3e-4
    step.ok = report.eq2_holds_at_paper_delta and agrees and report.beta_lt_q
    step.detail = (
        f"Eq2 holds={report.eq2_holds_at_paper_delta}; "
        f"delta={report.required_delta:.7f} vs estimator {estimator_delta:.7f} "
        f"({'agree' if agrees else 'DIVERGE'}); "
        f"BKZ k={report.required_blocksize:.0f}; "
        f"bits={report.min_cost_bits:.0f}-{max(v for v in report.costs_bits.values() if v):.0f}"
    )


def step_testnet(step: Step) -> None:
    code, out = run([PY, "tools/run_testnet.py"])
    succeeded = re.search(r"attacks that succeeded:\s*(\d+)", out)
    blocks = re.search(r"blocks\s*:\s*(\d+)", out)
    bad = int(succeeded.group(1)) if succeeded else -1
    step.ok = code == 0 and bad == 0
    step.detail = (
        f"blocks={blocks.group(1) if blocks else '?'}, "
        f"attacks_succeeded={bad if bad >= 0 else 'UNKNOWN'}"
    )


FORBIDDEN = (
    # (regex, why it is forbidden)
    (r"\bis\s+(?:cryptographically\s+)?secure\b", "unqualified security claim"),
    (r"\bproduction[- ]ready\b", "production-readiness claim"),
    (r"\bquantum[- ]proof\b", "absolute quantum claim (use post-quantum resistant)"),
    (r"\b128[- ]bit\s+secure\b", "uncertified bit-security claim"),
    (r"\bproven\s+secure\b", "no soundness/SHVZK/FS proof exists"),
)

# A forbidden phrase is FINE when it appears inside a negation or a
# meta-discussion of the phrase itself. Matching a bare "not" anywhere on the
# line is too loose (it fires on unrelated clauses) and too tight (it misses
# negations that sit far from the phrase), so require a negating cue that
# governs the claim: either it precedes the match, or the line is explicitly
# about forbidding/auditing the wording.
NEGATION_CUES = (
    "not", "never", "no ", "cannot", "can't", "nothing", "neither", "nor",
    "without", "lacks", "lacking", "absent", "unproven", "un-audited",
    "unaudited", "forbidden", "refuse", "reject", "must not", "may not",
    "would be", "claim", "claims", "audit", "grep", "regex", "pattern",
    "is not", "does not", "do not", "doesn't", "don't",
)


def _is_negated(line: str, match: re.Match) -> bool:
    """True when a negating cue governs this match.

    Checks the text BEFORE the match (a negation must precede the claim to
    govern it, e.g. "do not show that X is secure"), plus a whole-line check
    for lines that are explicitly about the forbidden wording.
    """
    before = line[: match.start()].lower()
    if any(cue in before for cue in NEGATION_CUES):
        return True
    lowered = line.lower()
    # Lines that define/audit the vocabulary rather than assert it.
    return any(
        marker in lowered
        for marker in ("forbidden", "claim audit", "must not", "never call")
    )


def step_security_frameworks(step: Step) -> None:
    """Fiat-Shamir and bit-security frameworks must stay HONEST.

    This step does not check a security level -- there isn't one. It checks
    that the frameworks still REFUSE to claim one while obligations are
    open. A regression here would mean the repo started overstating itself,
    which is the failure mode that matters most.
    """
    from pqct.fiat_shamir_framework import paper_framework
    from pqct.security_budget import paper_budget

    framework = paper_framework()
    budget = paper_budget()

    fs_open = len(framework.open_obligations)
    ok_fs = fs_open > 0 and "OPEN" in framework.overall_status
    ok_budget = (not budget.claimable) and "NO CLAIM" in budget.verdict
    # The M-SIS range must still match the hardness module.
    ok_msis = 85.0 <= budget.minimum_low <= 120.0

    step.ok = ok_fs and ok_budget and ok_msis
    step.detail = (
        f"FS: {fs_open}/{len(framework.open_obligations) + len(framework.discharged_obligations)}"
        f" open, soundness {framework.soundness_bits:.0f}b - forking "
        f"{framework.forking_loss:.0f}b - qrom {framework.qrom_loss:.0f}b "
        f"= {framework.residual_bits_optimistic:.0f}b; "
        f"budget capped by {budget.binding_component.name} "
        f"({budget.minimum_low:.0f}-{budget.minimum_high:.0f}b), "
        f"claimable={budget.claimable}"
    )


def audit_text(text: str) -> list[tuple[int, str]]:
    """Return [(line_no, why)] for forbidden claims in `text`.

    Shared by the stack-check step and its tests so the two can never drift
    apart. Uses a two-line window because negations wrap across line breaks.
    """
    hits = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        for pattern, why in FORBIDDEN:
            match = re.search(pattern, line, re.IGNORECASE)
            if not match or _is_negated(line, match):
                continue
            if index > 0:
                joined = lines[index - 1].rstrip() + " " + line
                joined_match = re.search(pattern, joined, re.IGNORECASE)
                if joined_match and _is_negated(joined, joined_match):
                    continue
            hits.append((index + 1, why))
    return hits


def audit_paths() -> list:
    paths = (
        list(ROOT.glob("pqct/*.py"))
        + list(ROOT.glob("tools/*.py"))
        + list(ROOT.glob("docs/*.md"))
        + [ROOT / "README.md"]
    )
    return [p for p in paths if p.exists() and p.name != "stack_check.py"]


def step_claim_audit(step: Step) -> None:
    """Fail on drift toward claims the crypto does not support."""
    hits = []
    for path in audit_paths():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, why in audit_text(text):
            hits.append(f"{path.relative_to(ROOT)}:{line_no}: {why}")
    step.ok = not hits
    step.detail = "no forbidden claims" if not hits else f"{len(hits)} hit(s): " + \
        "; ".join(hits[:3])


def main() -> int:
    print("=" * 74)
    print("CHITIN FULL-STACK CHECK")
    print("=" * 74)

    steps = [
        (Step("unit + adversarial tests"), step_pytest),
        (Step("compileall"), step_compile),
        (Step("paper number reproduction"), step_paper_reproduction),
        (Step("M-SIS Eq.(2) criterion"), step_msis_criterion),
        (Step("experimental testnet"), step_testnet),
        (Step("security frameworks stay honest"), step_security_frameworks),
        (Step("claim audit"), step_claim_audit),
    ]

    for step, fn in steps:
        started = time.perf_counter()
        try:
            fn(step)
        except Exception as error:  # noqa: BLE001 - a crash is a failure
            step.ok = False
            step.detail = f"{type(error).__name__}: {str(error)[:110]}"
        step.seconds = time.perf_counter() - started
        mark = "PASS" if step.ok else "FAIL"
        print(f"\n[{mark}] {step.name}  ({step.seconds:.1f}s)")
        print(f"       {step.detail}")

    failures = [s for s, _ in steps if not s.ok]
    print()
    print("=" * 74)
    if failures:
        print(f"STACK CHECK FAILED -- {len(failures)} step(s): "
              + ", ".join(s.name for s in failures))
        return 1
    print(f"STACK CHECK PASSED -- all {len(steps)} steps green")
    print("Standing caveat: plumbing is tested; the underlying proofs are")
    print("UNPROVEN research crypto. No bit-security level is certified.")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
