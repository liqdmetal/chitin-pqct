"""Tests for the claim-audit detector in tools/stack_check.py.

A drift detector that cannot be trusted is worse than no detector: a false
negative lets an overclaim ship, and a false positive trains everyone to
ignore the gate. So the detector itself gets tested against known positives
and known negations.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from stack_check import FORBIDDEN, _is_negated, audit_paths, audit_text


def flagged(line: str) -> bool:
    """Single-line check (no wrap context), for the vocabulary tests."""
    return bool(audit_text(line))


class ClaimAuditDetectorTests(unittest.TestCase):
    def test_flags_real_overclaims(self):
        for line in (
            "This scheme is secure against all known attacks.",
            "The implementation is production-ready.",
            "Chitin is quantum-proof.",
            "Our parameters are 128-bit secure.",
            "The construction is proven secure in the ROM.",
            "It is cryptographically secure.",
        ):
            with self.subTest(line=line):
                self.assertTrue(flagged(line), f"missed overclaim: {line}")

    def test_allows_negated_and_meta_statements(self):
        for line in (
            "They do not show that the complete Gao construction is secure, "
            "post-quantum, or suitable for consensus.",
            "Neither one proves that a lattice commitment or its "
            "zero-knowledge proof is secure.",
            "Nothing here is production-ready.",
            "This is never quantum-proof; use post-quantum resistant.",
            "We cannot claim it is secure.",
            "No component is proven secure.",
        ):
            with self.subTest(line=line):
                self.assertFalse(flagged(line), f"false positive: {line}")

    def test_negation_must_precede_the_claim(self):
        """A trailing 'not' about something else must NOT excuse the claim."""
        self.assertTrue(flagged("The scheme is secure, whether or not audited."))

    def test_repository_is_currently_clean(self):
        """The live tree must pass its own audit (same code path as the gate)."""
        root = Path(__file__).resolve().parent.parent
        hits = []
        for path in audit_paths():
            text = path.read_text(encoding="utf-8", errors="replace")
            for line_no, _why in audit_text(text):
                hits.append(f"{path.relative_to(root)}:{line_no}")
        self.assertEqual(hits, [], f"forbidden claims present: {hits}")

    def test_wrapped_negation_is_allowed(self):
        """Negations that wrap across a line break must not be flagged."""
        wrapped = (
            "They do not show that the complete Gao construction\n"
            "is secure, post-quantum, or suitable for consensus."
        )
        self.assertEqual(audit_text(wrapped), [])


if __name__ == "__main__":
    unittest.main()
