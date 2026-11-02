import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scanner.py'


class ScannerOptionsTests(unittest.TestCase):
    def test_exclusion_and_severity_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'fixtures').mkdir()
            (root / 'fixtures' / 'sample.py').write_text('eval(user_input)', encoding='utf-8')
            (root / 'app.js').write_text('node.innerHTML = value;', encoding='utf-8')
            result = subprocess.run([sys.executable, str(SCRIPT), str(root), '--exclude', 'fixtures', '--fail-on', 'medium'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual([item['rule'] for item in json.loads(result.stdout)['findings']], ['WEB-INNERHTML'])
            report = subprocess.run([sys.executable, str(SCRIPT), str(root), '--exclude', 'fixtures', '--fail-on', 'none'], capture_output=True, text=True)
            self.assertEqual(report.returncode, 0)

    def test_exclusion_is_a_name_not_a_path(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(SCRIPT), directory, '--exclude', '../outside'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('without path separators', result.stderr)


if __name__ == '__main__':
    unittest.main()
