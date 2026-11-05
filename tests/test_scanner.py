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

    def test_ignores_python_comments_and_literal_strings_without_losing_line_numbers(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'examples.py').write_text(
                '# eval(untrusted)\n'
                'description = "shell=True and exec(code)"\n'
                'documentation = """\n'
                'eval(malicious)\n'
                '"""\n'
                'result = eval(user_input)  # exec(ignored)\n'
                'subprocess.run(argv, shell=True)\n',
                encoding='utf-8',
            )
            found = scan(root)
            self.assertEqual([(x['rule'], x['line']) for x in found],
                             [('PY-EVAL', 6), ('PY-SHELL', 7)])

    def test_fstring_interpolations_are_scanned_as_executable_python(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'formatted.py').write_text(
                'plain = "eval(ignored)"\n'
                'dynamic = f"{eval(user_input)}"\n'
                'raw_dynamic = rf"value:{exec(code)}"\n',
                encoding='utf-8',
            )
            found = scan(root)
            self.assertEqual(
                [(item['rule'], item['line']) for item in found],
                [('PY-EVAL', 2), ('PY-EVAL', 3)],
            )

    def test_js_comments_and_strings_do_not_create_false_alarms(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'web.ts').write_text(
                '// eval(in_comment)\n'
                '/* node.innerHTML = in_comment\n'
                'eval(in_comment) */\n'
                'const harmless = "eval(in_string)";\n'
                "const url = 'https://example.com';\n"
                'eval(actual);\n'
                'element.innerHTML = content;\n',
                encoding='utf-8',
            )
            self.assertEqual(
                [(item['rule'], item['line']) for item in scan(root)],
                [('JS-EVAL', 6), ('WEB-INNERHTML', 7)],
            )

    def test_js_template_text_is_ignored_but_interpolation_is_scanned(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            tick = chr(96)
            expression = '
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
 + '{eval(user)}'
            (root / 'web.js').write_text(
                'const text = ' + tick + 'eval(inert) ' + expression + tick + ';\n'
                + 'const ignored = ' + tick + 'node.innerHTML = harmless' + tick + ';\n'
                + 'const dynamic = ' + tick + '
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
 + '{({ key: eval(actual) })}' + tick + ';\n',
                encoding='utf-8',
            )
            self.assertEqual(
                [(item['rule'], item['line']) for item in scan(root)],
                [('JS-EVAL', 1), ('JS-EVAL', 3)],
            )

    def test_js_incomplete_literal_falls_back_to_conservative_raw_scan(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'incomplete.js').write_text('const unfinished = "eval(foo)', encoding='utf-8')
            self.assertEqual(
                [(item['rule'], item['line']) for item in scan(root)],
                [('JS-EVAL', 1)],
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
