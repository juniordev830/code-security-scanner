"""Bounded, read-only static text scanner; heuristic findings, not proof of exploits."""
from __future__ import annotations
import argparse
import json
import os
import re
import stat
from pathlib import Path

RULES = (
    ('PY-EVAL', 'high', re.compile(r'\b(?:eval|exec)\s*\('), 'Dynamic Python execution'),
    ('PY-SHELL', 'high', re.compile(r'\bshell\s*=\s*True\b'), 'Shell execution enabled'),
    ('WEB-INNERHTML', 'medium', re.compile(r'\.innerHTML\s*='), 'Review DOM HTML insertion'),
)
EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx'}
SKIP = {'.git', 'node_modules', '.venv', 'dist', 'build', '__pycache__'}
MAX_FILE_BYTES = 256_000


def _read_source(file: Path) -> str | None:
    """Read only regular files, bounded even if their size changes after stat."""
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(file, flags)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                return None
            raw = stream.read(MAX_FILE_BYTES + 1)
            if len(raw) > MAX_FILE_BYTES:
                return None
        return raw.decode('utf-8')
    except (OSError, UnicodeDecodeError):
        return None


def sarif_report(findings: list[dict]) -> dict:
    """Convert heuristic findings to SARIF 2.1.0 for CI code-scanning uploads."""
    levels = {'high': 'error', 'medium': 'warning', 'low': 'note'}
    rules = {}
    results = []
    for finding in findings:
        rule_id = finding['rule']
        rules.setdefault(rule_id, {
            'id': rule_id,
            'shortDescription': {'text': finding['message']},
            'defaultConfiguration': {'level': levels.get(finding['severity'], 'warning')},
        })
        results.append({
            'ruleId': rule_id,
            'level': levels.get(finding['severity'], 'warning'),
            'message': {'text': finding['message']},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': finding['file']},
                    'region': {'startLine': finding['line']},
                }
            }],
        })
    return {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {'name': 'code-security-scanner', 'rules': list(rules.values())}},
            'results': results,
        }],
    }

def scan(root: Path, exclude: set[str] | None = None) -> list[dict]:
    root = root.resolve()
    skipped = SKIP | (exclude or set())
    findings = []

    # Prune excluded directories before traversal. Path.rglob() would still
    # enumerate every nested file inside node_modules/.venv/dist/build.
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in skipped and not (current / name).is_symlink()
        )

        for filename in sorted(filenames):
            file = current / filename
            if file.suffix.lower() not in EXTENSIONS or file.is_symlink():
                continue
            source = _read_source(file)
            if source is None:
                continue

            for line_number, line in enumerate(source.splitlines(), 1):
                for rule_id, severity, pattern, message in RULES:
                    if pattern.search(line):
                        findings.append({
                            'file': file.relative_to(root).as_posix(),
                            'line': line_number, 'rule': rule_id,
                            'severity': severity, 'message': message,
                        })
    return findings

def main() -> int:
    cli = argparse.ArgumentParser(description='Read-only source scanner')
    cli.add_argument('directory', nargs='?', default='.')
    cli.add_argument('--exclude', action='append', default=[], metavar='NAME',
                     help='skip an additional directory name (repeatable)')
    cli.add_argument('--fail-on', choices=('high', 'medium', 'none'), default='high',
                     help='minimum severity that returns exit code 1 (default: high)')
    cli.add_argument('--format', choices=('json', 'sarif'), default='json',
                     help='output format for findings (default: json)')
    args = cli.parse_args()
    if any(not name or name in {'.', '..'} or '/' in name or '\\' in name for name in args.exclude):
        cli.error('exclude must be a directory name without path separators')
    path = Path(args.directory)
    if not path.is_dir():
        cli.error('directory not found')
    findings = scan(path, exclude=set(args.exclude))
    report = sarif_report(findings) if args.format == 'sarif' else {
        'findings': findings,
        'total': len(findings),
    }
    print(json.dumps(report, indent=2))
    severities = {'high': 2, 'medium': 1}
    thresholds = {'high': 2, 'medium': 1, 'none': 3}
    return 1 if any(severities[x['severity']] >= thresholds[args.fail_on] for x in findings) else 0

if __name__ == '__main__':
    raise SystemExit(main())
