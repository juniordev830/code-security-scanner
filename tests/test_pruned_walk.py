import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner import scan


class DirectoryPruningTests(unittest.TestCase):
    def test_excluded_directories_are_not_traversed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'src').mkdir()
            (root / 'src' / 'app.py').write_text('eval(user_input)\n', encoding='utf-8')
            (root / 'src' / 'node_modules').mkdir()
            (root / 'src' / 'node_modules' / 'ignored.py').write_text('exec(code)\n', encoding='utf-8')
            (root / 'vendor' / 'nested').mkdir(parents=True)
            (root / 'vendor' / 'nested' / 'ignored.py').write_text('exec(code)\n', encoding='utf-8')

            visited = []
            original_walk = os.walk

            def recording_walk(*args, **kwargs):
                for current, dirs, files in original_walk(*args, **kwargs):
                    visited.append(Path(current).relative_to(root).as_posix())
                    yield current, dirs, files

            with patch('scanner.os.walk', side_effect=recording_walk):
                findings = scan(root, exclude={'vendor'})

            self.assertEqual([(x['file'], x['rule']) for x in findings],
                             [('src/app.py', 'PY-EVAL')])
            self.assertIn('src', visited)
            self.assertNotIn('src/node_modules', visited)
            self.assertNotIn('vendor', visited)

    def test_symlinked_directories_are_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            (source / 'sample.py').write_text('exec(data)\n', encoding='utf-8')
            link = root / 'linked'
            try:
                link.symlink_to(source, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest('Directory symlinks are not supported on this machine')
            findings = scan(root)
            self.assertEqual([(x['file'], x['rule']) for x in findings],
                             [('source/sample.py', 'PY-EVAL')])


if __name__ == '__main__':
    unittest.main()
