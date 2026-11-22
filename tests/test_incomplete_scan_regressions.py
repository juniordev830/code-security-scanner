"""Regression tests for incomplete scans: never report unreadable input as clean."""
import tempfile
import unittest
from pathlib import Path

from scanner import INCOMPLETE_SCAN_RULE, MAX_FILE_BYTES, scan


class IncompleteScanTests(unittest.TestCase):
    def test_invalid_utf8_source_is_reported_as_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "invalid.py").write_bytes(b"\xff\xfe")
            findings = scan(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], INCOMPLETE_SCAN_RULE)
            self.assertEqual(findings[0]["file"], "invalid.py")

    def test_oversized_source_is_reported_as_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.py").write_bytes(b"x" * (MAX_FILE_BYTES + 1))
            findings = scan(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], INCOMPLETE_SCAN_RULE)
            self.assertIn("256 KB", findings[0]["message"])


if __name__ == "__main__":
    unittest.main()
