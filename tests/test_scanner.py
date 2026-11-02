import tempfile
import unittest
from pathlib import Path
from scanner import scan

class ScannerTests(unittest.TestCase):
    def test_flags_dangerous_patterns_without_running_code(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'app.py').write_text('result = eval(user_input)\n', encoding='utf-8')
            (root/'app.js').write_text('node.innerHTML = text;\n', encoding='utf-8')
            found = scan(root)
            self.assertEqual({x['rule'] for x in found}, {'PY-EVAL', 'WEB-INNERHTML'})
            self.assertTrue(all(x['line'] == 1 for x in found))
    def test_skips_dependencies(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'node_modules').mkdir()
            (root/'node_modules'/'bad.py').write_text('exec(code)')
            self.assertEqual(scan(root), [])

if __name__ == '__main__': unittest.main()
