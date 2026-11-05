"""Bounded, read-only static text scanner; heuristic findings, not proof of exploits."""
from __future__ import annotations
import argparse
import io
import json
import re
import tokenize
from pathlib import Path

PYTHON = frozenset({'.py'})
JAVASCRIPT = frozenset({'.js', '.ts', '.jsx', '.tsx'})
RULES = (
    ('PY-EVAL', 'high', re.compile(r'\b(?:eval|exec)\s*\('), 'Dynamic Python execution', PYTHON),
    ('PY-SHELL', 'high', re.compile(r'\bshell\s*=\s*True\b'), 'Shell execution enabled', PYTHON),
    ('JS-EVAL', 'high', re.compile(r'\beval\s*\('), 'Dynamic JavaScript execution', JAVASCRIPT),
    ('WEB-INNERHTML', 'medium', re.compile(r'\.innerHTML\s*='), 'Review DOM HTML insertion', JAVASCRIPT),
)
EXTENSIONS = PYTHON | JAVASCRIPT
SKIP = {'.git', 'node_modules', '.venv', 'dist', 'build', '__pycache__'}
MAX_FILE_BYTES = 256_000


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

def mask_python_literals(source: str) -> str:
    """Mask Python comments and strings, retaining line numbers for findings.

    Falls back to the raw heuristic for incomplete or invalid Python, rather
    than silently dropping findings while the file is being edited.
    """
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    masked = list(source)
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type not in (tokenize.STRING, tokenize.COMMENT):
                continue
            start = offsets[token.start[0] - 1] + token.start[1]
            end = offsets[token.end[0] - 1] + token.end[1]
            for index in range(start, end):
                if masked[index] not in '\r\n':
                    masked[index] = ' '
    except (tokenize.TokenError, IndentationError):
        return source
    return ''.join(masked)


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
        searchable = mask_python_literals(source) if file.suffix.lower() in PYTHON else source
        for line_number, line in enumerate(searchable.splitlines(), 1):
            for rule_id, severity, pattern, message, extensions in RULES:
                if file.suffix.lower() in extensions and pattern.search(line):
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
