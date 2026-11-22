"""Regressões da regra de execução de shell com os.system."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from scanner import scan


class OsSystemRuleTests(unittest.TestCase):
    def test_detects_real_os_system_calls(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "example.py"
            path.write_text(
                "import os\ncommand = 'echo example'\nos.system(command)\n",
                encoding="utf-8",
            )
            findings = scan(Path(directory))
        self.assertEqual([(f["line"], f["rule"]) for f in findings],
                         [(3, "PY-OS-SYSTEM")])

    def test_ignores_references_in_strings_comments_and_declarations(self):
        with TemporaryDirectory() as directory:
            (Path(directory) / "safe.py").write_text(
                '# os.system("hello")\n'
                'text = "os.system(hello)"\n'
                'def system(value):\n    return value\n',
                encoding="utf-8",
            )
            self.assertEqual(scan(Path(directory)), [])


if __name__ == "__main__":
    unittest.main()
