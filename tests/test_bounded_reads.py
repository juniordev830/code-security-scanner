import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scanner import MAX_FILE_BYTES, scan


class BoundedReadTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_accepts_exact_byte_limit(self):
        content = b'eval(value)\n'
        (self.root / 'app.py').write_bytes(content + b' ' * (MAX_FILE_BYTES - len(content)))
        self.assertEqual(len(scan(self.root)), 1)

    def test_rejects_one_byte_above_limit(self):
        (self.root / 'app.py').write_bytes(b'eval(value)' + b' ' * MAX_FILE_BYTES)
        self.assertEqual(scan(self.root), [])

    def test_bounded_read_rejects_growth_after_size_check(self):
        (self.root / 'app.py').write_bytes(b'eval(value)' + b' ' * MAX_FILE_BYTES)
        original = os.fstat

        def stale_size(descriptor):
            info = original(descriptor)
            return SimpleNamespace(st_mode=info.st_mode, st_size=1)

        with patch('scanner.os.fstat', side_effect=stale_size):
            self.assertEqual(scan(self.root), [])

    def test_invalid_utf8_is_skipped(self):
        (self.root / 'bad.py').write_bytes(b'eval(value)\xff')
        self.assertEqual(scan(self.root), [])

    def test_symlinked_files_are_skipped(self):
        target = self.root / 'original.txt'
        target.write_text('eval(value)', encoding='utf-8')
        try:
            (self.root / 'linked.py').symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest('File symlinks are unavailable')
        self.assertEqual(scan(self.root), [])

    @unittest.skipUnless(hasattr(os, 'mkfifo') and hasattr(os, 'O_NONBLOCK'), 'Requires POSIX FIFOs')
    def test_named_pipe_does_not_block_scanning(self):
        os.mkfifo(self.root / 'blocked.py')
        script = Path(__file__).resolve().parents[1] / 'scanner.py'
        result = subprocess.run([sys.executable, str(script), str(self.root)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"total": 0', result.stdout)
