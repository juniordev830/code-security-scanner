import tempfile
import unittest
from pathlib import Path
from scanner import scan


class OsAliasTests(unittest.TestCase):
    def test_os_alias_and_from_import_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "calls.py").write_text(
                "import os as operating_system\n"
                "from os import system as run_shell\n"
                "operating_system.system(command)\n"
                "run_shell(command)\n"
                "other.system(command)\n",
                encoding="utf-8",
            )
            self.assertEqual(
                [(item["line"], item["rule"]) for item in scan(Path(directory))],
                [(3, "PY-OS-SYSTEM"), (4, "PY-OS-SYSTEM")],
            )


if __name__ == "__main__":
    unittest.main()
