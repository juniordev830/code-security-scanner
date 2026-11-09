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
    def test_python_strings_and_comments_do_not_trigger_high_severity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'example.py').write_text(
                'message = "eval(untrusted)"\\n'
                '# exec(untrusted)\\n'
                'documentation = """\\n'
                'shell=True\\n'
                'eval(data)\\n'
                '"""\\n'
                'value = eval(user_input)\\n'
                'subprocess.run(command, shell=True)\\n',
                encoding='utf-8',
            )
            result = scan(root)
            self.assertEqual(
                [(item['line'], item['rule']) for item in result],
                [(7, 'PY-EVAL'), (8, 'PY-SHELL')],
            )

    def test_rules_apply_only_to_supported_languages(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'client.ts').write_text(
                'eval(data);\\nnode.innerHTML = html;\\n', encoding='utf-8'
            )
            (root / 'logic.py').write_text(
                'node.innerHTML = content\\nexec(code)\\n', encoding='utf-8'
            )
            result = scan(root)
            self.assertEqual(
                {(item['file'], item['rule']) for item in result},
                {('client.ts', 'WEB-INNERHTML'), ('logic.py', 'PY-EVAL')},
            )

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
