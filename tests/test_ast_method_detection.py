"""Regressions: method calls named eval/exec are not Python builtins."""
import tempfile
import unittest
from pathlib import Path
from scanner import scan


class AstCallPrecisionTests(unittest.TestCase):
    def test_unrelated_methods_do_not_trigger_builtin_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "objects.py").write_text(
                "document.eval('expression')\n"
                "service.exec('task')\n"
                "value = f'{helper.eval(payload)}'\n",
                encoding="utf-8",
            )
            self.assertEqual(scan(root), [])

    def test_builtin_eval_and_exec_still_trigger(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "actual.py").write_text(
                "result = eval(user_input)\n"
                "exec(another_input)\n",
                encoding="utf-8",
            )
            self.assertEqual(
                [(finding["line"], finding["rule"]) for finding in scan(root)],
                [(1, "PY-EVAL"), (2, "PY-EVAL")],
            )


if __name__ == "__main__":
    unittest.main()
