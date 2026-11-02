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

def scan(root: Path, exclude: set[str] | None = None) -> list[dict]:
    root = root.resolve()
    skipped = SKIP | (exclude or set())
    findings = []
    for file in sorted(root.rglob('*')):
        if not file.is_file() or file.suffix.lower() not in EXTENSIONS:
            continue
        if any(part in skipped for part in file.relative_to(root).parts[:-1]):
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
    cli.add_argument('--exclude', action='append', default=[], metavar='NAME',
                     help='skip an additional directory name (repeatable)')
    cli.add_argument('--fail-on', choices=('high', 'medium', 'none'), default='high',
                     help='minimum severity that returns exit code 1 (default: high)')
    args = cli.parse_args()
    if any(not name or name in {'.', '..'} or '/' in name or '\\' in name for name in args.exclude):
        cli.error('exclude must be a directory name without path separators')
    path = Path(args.directory)
    if not path.is_dir():
        cli.error('directory not found')
    findings = scan(path, exclude=set(args.exclude))
    print(json.dumps({'findings': findings, 'total': len(findings)}, indent=2))
    severities = {'high': 2, 'medium': 1}
    thresholds = {'high': 2, 'medium': 1, 'none': 3}
    return 1 if any(severities[x['severity']] >= thresholds[args.fail_on] for x in findings) else 0

if __name__ == '__main__':
    raise SystemExit(main())
