import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import scanner


SCRIPT = Path(__file__).resolve().parents[1] / 'scanner.py'


class IncompleteScanTests(unittest.TestCase):
    def test_oversized_file_is_reported_as_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'large.py').write_bytes(b'x' * (scanner.MAX_FILE_BYTES + 1))

            findings = scanner.scan(root)

            self.assertEqual(
                [(item['file'], item['rule']) for item in findings],
                [('large.py', 'SCAN-INCOMPLETE')],
            )

    def test_unreadable_file_is_reported_as_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'private.py'
            target.write_text('eval(user_input)\n', encoding='utf-8')
            original_open = os.open

            def deny_target(path, flags, *args, **kwargs):
                if Path(path) == target:
                    raise PermissionError('simulated unreadable source')
                return original_open(path, flags, *args, **kwargs)

            with patch('scanner.os.open', side_effect=deny_target):
                findings = scanner.scan(root)

            self.assertEqual(
                [(item['file'], item['rule']) for item in findings],
                [('private.py', 'SCAN-INCOMPLETE')],
            )

    def test_non_regular_source_file_is_reported_without_blocking(self):
        if not hasattr(os, 'mkfifo'):
            self.skipTest('Named pipes are not supported on this platform')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fifo = root / 'stream.py'
            os.mkfifo(fifo)

            findings = scanner.scan(root)

            self.assertEqual(
                [(item['file'], item['rule']) for item in findings],
                [('stream.py', 'SCAN-INCOMPLETE')],
            )

    def test_directory_walk_error_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def failing_walk(*args, **kwargs):
                callback = kwargs['onerror']
                callback(PermissionError(13, 'permission denied', str(root / 'locked')))
                return iter(())

            with patch('scanner.os.walk', side_effect=failing_walk):
                findings = scanner.scan(root)

            self.assertEqual(
                [(item['file'], item['rule']) for item in findings],
                [('locked', 'SCAN-INCOMPLETE')],
            )

    def test_incomplete_scan_fails_even_when_findings_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'large.py').write_bytes(b'x' * (scanner.MAX_FILE_BYTES + 1))

            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(root), '--fail-on', 'none'],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            report = json.loads(result.stdout)
            self.assertEqual(report['findings'][0]['rule'], 'SCAN-INCOMPLETE')



    def test_library_scan_rejects_missing_or_file_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / 'single.py'
            file.write_text('print(1)', encoding='utf-8')
            with self.assertRaises(ValueError):
                scanner.scan(file)
            with self.assertRaises(ValueError):
                scanner.scan(root / 'missing')


if __name__ == '__main__':
    unittest.main()
