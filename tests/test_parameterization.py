import json
import unittest

from pqct.parameterization import ParameterCandidate, candidate_set, render_report


class ParameterizationTests(unittest.TestCase):
    def test_candidates_are_explicitly_unassessed(self):
        candidates = candidate_set()
        self.assertEqual(len(candidates), 2)
        self.assertTrue(all(c.security_label == "UNASSESSED_RESEARCH_CANDIDATE" for c in candidates))
        self.assertTrue(all(c.q % (2 * c.n) == 1 for c in candidates))

    def test_invalid_ntt_modulus_rejected(self):
        with self.assertRaises(ValueError):
            ParameterCandidate("bad", 32, 12291, 8, 32, 16, 8, 8, 2, 2, 3.2, 2.4, 15, 256, 256)

    def test_report_is_machine_readable_and_warns(self):
        report = json.loads(render_report())
        self.assertEqual(report["status"], "research-only")
        self.assertEqual(len(report["candidates"]), 2)
        self.assertTrue(any("Module-SIS" in warning for warning in report["candidates"][0]["warnings"]))


if __name__ == "__main__":
    unittest.main()
