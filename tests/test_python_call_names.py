"""Regression coverage for calls to unrelated methods named eval/exec."""
import tempfile
import unittest
from pathlib import Path

from scanner import scan


class PythonCallNameTests(unittest.TestCase):
    def test_object_methods_are_not_python_dynamic_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "methods.py"
            source.write_text(
                "class Calculator:\n"
                "    def eval(self):\n"
                "        return 42\n"
                "    def exec(self):\n"
                "        return 21\n"
                "calculator = Calculator()\n"
                "calculator.eval()\n"
                "calculator.exec()\n", encoding="utf-8"
            )
            self.assertEqual(scan(Path(directory)), [])

    def test_builtin_eval_still_reports_high_severity(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "danger.py").write_text("eval('1 + 1')\n", encoding="utf-8")
            findings = scan(Path(directory))
            self.assertEqual([item["rule"] for item in findings], ["PY-EVAL"])


if __name__ == "__main__":
    unittest.main()
