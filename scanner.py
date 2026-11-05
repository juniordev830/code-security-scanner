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
    # Python 3.12+ exposes f-string expression tokens; mask only literal
    # FSTRING_MIDDLE spans. Older versions expose an entire f-string as STRING.
    # Preserve those whole tokens to avoid hiding eval/exec inside { ... }.
    mask_types = {tokenize.STRING, tokenize.COMMENT}
    fstring_middle = getattr(tokenize, 'FSTRING_MIDDLE', None)
    if fstring_middle is not None:
        mask_types.add(fstring_middle)
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type not in mask_types:
                continue
            if token.type == tokenize.STRING and re.match(r"(?i)^(?:fr|rf|f)['\\\"]", token.string):
                continue
            start = offsets[token.start[0] - 1] + token.start[1]
            end = offsets[token.end[0] - 1] + token.end[1]
            for index in range(start, end):
                if masked[index] not in '\r\n':
                    masked[index] = ' '
    except (tokenize.TokenError, IndentationError):
        return source
    return ''.join(masked)



def mask_javascript_literals(source: str) -> str:
    """Mask JS comments and literal text, preserving template expressions.

    This is a heuristic, not a full JavaScript/TypeScript parser. If syntax is
    unfinished, preserve raw source instead of silently hiding findings.
    """
    masked = list(source)
    length = len(source)

    def hide(start: int, end: int) -> None:
        for index in range(start, min(end, length)):
            if source[index] not in '\r\n':
                masked[index] = ' '

    def quoted(start: int) -> int:
        quote = source[start]
        cursor = start + 1
        while cursor < length:
            if source[cursor] == '\\':
                cursor += 2
            elif source[cursor] == quote:
                hide(start, cursor + 1)
                return cursor + 1
            else:
                cursor += 1
        raise ValueError('unfinished string')

    def comment(start: int) -> int:
        if source[start + 1] == '/':
            end = source.find('\n', start + 2)
            if end < 0:
                end = length
            hide(start, end)
            return end
        end = source.find('*/', start + 2)
        if end < 0:
            raise ValueError('unfinished block comment')
        hide(start, end + 2)
        return end + 2

    def template(start: int) -> int:
        hide(start, start + 1)
        cursor = start + 1
        while cursor < length:
            if source[cursor] == '\\':
                hide(cursor, cursor + 2)
                cursor += 2
            elif source[cursor] == chr(96):
                hide(cursor, cursor + 1)
                return cursor + 1
            elif source.startswith(chr(36) + '{', cursor):
                hide(cursor, cursor + 2)
                cursor = code(cursor + 2, template_expr=True)
            else:
                hide(cursor, cursor + 1)
                cursor += 1
        raise ValueError('unfinished template')

    def code(start: int, template_expr: bool = False) -> int:
        depth = 1 if template_expr else 0
        cursor = start
        while cursor < length:
            if source[cursor] in ("'", '"'):
                cursor = quoted(cursor)
            elif source[cursor] == chr(96):
                cursor = template(cursor)
            elif source[cursor] == '/' and cursor + 1 < length and source[cursor + 1] in '/*':
                cursor = comment(cursor)
            elif template_expr and source[cursor] == '{':
                depth += 1
                cursor += 1
            elif template_expr and source[cursor] == '}':
                depth -= 1
                if depth == 0:
                    hide(cursor, cursor + 1)
                    return cursor + 1
                cursor += 1
            else:
                cursor += 1
        if template_expr:
            raise ValueError('unfinished template interpolation')
        return cursor

    try:
        code(0)
    except ValueError:
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
        if file.suffix.lower() in PYTHON:
            searchable = mask_python_literals(source)
        elif file.suffix.lower() in JAVASCRIPT:
            searchable = mask_javascript_literals(source)
        else:
            searchable = source
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
 + '{', cursor):
                hide(cursor, cursor + 2)
                cursor = code(cursor + 2, template_expr=True)
            else:
                hide(cursor, cursor + 1)
                cursor += 1
        raise ValueError('unfinished template')

    def code(start: int, template_expr: bool = False) -> int:
        depth = 1 if template_expr else 0
        cursor = start
        while cursor < length:
            if source[cursor] in ("'", '"'):
                cursor = quoted(cursor)
            elif source[cursor] == chr(96):
                cursor = template(cursor)
            elif source[cursor] == '/' and cursor + 1 < length and source[cursor + 1] in '/*':
                cursor = comment(cursor)
            elif template_expr and source[cursor] == '{':
                depth += 1
                cursor += 1
            elif template_expr and source[cursor] == '}':
                depth -= 1
                if depth == 0:
                    hide(cursor, cursor + 1)
                    return cursor + 1
                cursor += 1
            else:
                cursor += 1
        if template_expr:
            raise ValueError('unfinished template interpolation')
        return cursor

    try:
        code(0)
    except ValueError:
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
