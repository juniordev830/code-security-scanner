import tempfile
import unittest
from pathlib import Path
from scanner import sarif_report, scan

class ScannerTests(unittest.TestCase):
    def test_flags_dangerous_patterns_without_running_code(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'app.py').write_text('result = eval(user_input)\n', encoding='utf-8')
            (root/'app.js').write_text('node.innerHTML = text;\n', encoding='utf-8')
            found = scan(root)
            self.assertEqual({x['rule'] for x in found}, {'PY-EVAL', 'WEB-INNERHTML'})
            self.assertTrue(all(x['line'] == 1 for x in found))
    def test_rules_match_their_language(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'web.js').write_text('eval(source);\nshell=True;\n', encoding='utf-8')
            (root/'worker.py').write_text('exec(source)\nelement.innerHTML = text\n', encoding='utf-8')
            rules = {}
            for finding in scan(root):
                rules.setdefault(finding['file'], set()).add(finding['rule'])
            self.assertEqual(rules['web.js'], {'JS-EVAL'})
            self.assertEqual(rules['worker.py'], {'PY-EVAL'})

    def test_serializes_findings_as_sarif(self):
        report = sarif_report([{
            'file': 'app.py', 'line': 4, 'rule': 'PY-EVAL',
            'severity': 'high', 'message': 'Dynamic Python execution'
        }])
        self.assertEqual(report['version'], '2.1.0')
        self.assertEqual(report['runs'][0]['results'][0]['ruleId'], 'PY-EVAL')
        self.assertEqual(report['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine'], 4)

    def test_skips_dependencies(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'node_modules').mkdir()
            (root/'node_modules'/'bad.py').write_text('exec(code)')
            self.assertEqual(scan(root), [])

if __name__ == '__main__': unittest.main()
