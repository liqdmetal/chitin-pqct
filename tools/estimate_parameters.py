"""Print HMC binding-parameter check + lattice hardness estimate (research-only)."""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqct.hmc_binding_reduction import check_binding_parameters
from pqct.lattice_estimate import LatticeEstimateError
from pqct.lattice_estimate import estimate_sis_hardness
from pqct.parameterization import candidate_set
from pqct.parameters import GaoPaperProfile


def _entry(name, n, d, q, beta_bound, dimension_note):
    try:
        estimate = estimate_sis_hardness(n=n, d=d, q=q, beta_bound=beta_bound)
    except LatticeEstimateError as error:
        return {
            "candidate": name, "n": n, "d": d, "q": q,
            "beta_bound": beta_bound,
            "dimension_note": dimension_note,
            "error": str(error),
        }
    binding = check_binding_parameters(
        n=n, d=d, q=q,
        delta=estimate.required_delta, beta=beta_bound,
    )
    return {
        "candidate": name, "n": n, "d": d, "q": q,
        "beta_bound": beta_bound,
        "dimension_note": dimension_note,
        "required_delta": estimate.required_delta,
        "bkz_blocksize": estimate.bkz_blocksize,
        "classical_bits": estimate.classical_bits,
        "quantum_bits": estimate.quantum_bits,
        "paranoid_bits": estimate.paranoid_bits,
        "is_lower_bound": estimate.is_lower_bound,
        "binding_equation_2_passes": binding.passes,
    }


def main() -> None:
    results = []
    for c in candidate_set():
        results.append(_entry(
            c.name, c.n, c.d, c.q, c.response_bound,
            "CONFLATED: ParameterCandidate.n is ring degree, not SIS "
            "rank -- this candidate has no distinct module-rank value, "
            "so n=d here; treat these numbers as not meaningful for "
            "SIS-rank-sensitive hardness.",
        ))
    paper = GaoPaperProfile()
    paper.validate()
    results.append(_entry(
        "gao-paper-reported-profile", paper.n, paper.d, paper.q,
        256,
        "CORRECT: n=SIS rank, d=ring degree are independent, as in "
        "Gao Definition 1. Uses an illustrative beta_bound=256, not "
        "the paper's own derived T1/T2 bound.",
    ))
    print(json.dumps({
        "warning": (
            "self-built core-SVP estimate; NOT the verified "
            "Albrecht/Player/Scott lattice-estimator tool; no "
            "security claim; research-only"
        ),
        "results": results,
    }, indent=2))


if __name__ == "__main__":
    main()
