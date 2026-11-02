"""Bounded, read-only static text scanner; heuristic findings, not proof of exploits."""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

RULES = (
    ('PY-EVAL', 'high', re.compile(r'\b(?:eval|exec)\s*\('), 'Dynamic Python execution'),
    ('PY-SHELL', 'high', re.compile(r'\bshell\s*=\s*True\b'), 'Shell execution enabled'),
    ('WEB-INNERHTML', 'medium', re.compile(r'\.innerHTML\s*='), 'Review DOM HTML insertion'),
)
EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx'}
SKIP = {'.git', 'node_modules', '.venv', 'dist', 'build', '__pycache__'}
MAX_FILE_BYTES = 256_000

def scan(root: Path) -> list[dict]:
    root = root.resolve()
    findings = []
    for file in sorted(root.rglob('*')):
        if not file.is_file() or file.suffix.lower() not in EXTENSIONS:
            continue
        if any(part in SKIP for part in file.relative_to(root).parts):
            continue
        if file.is_symlink() or file.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            source = file.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(source.splitlines(), 1):
            for rule_id, severity, pattern, message in RULES:
                if pattern.search(line):
                    findings.append({'file': file.relative_to(root).as_posix(),
                                     'line': line_number, 'rule': rule_id,
                                     'severity': severity, 'message': message})
    return findings

def main() -> int:
    cli = argparse.ArgumentParser(description='Read-only source scanner')
    cli.add_argument('directory', nargs='?', default='.')
    args = cli.parse_args()
    path = Path(args.directory)
    if not path.is_dir():
        cli.error('directory not found')
    findings = scan(path)
    print(json.dumps({'findings': findings, 'total': len(findings)}, indent=2))
    return 1 if any(x['severity'] == 'high' for x in findings) else 0

if __name__ == '__main__':
    raise SystemExit(main())
