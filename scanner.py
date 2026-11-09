"""Bounded, read-only static text scanner; heuristic findings, not proof of exploits."""
from __future__ import annotations
import argparse
import ast
import io
import json
import os
import re
import tokenize
from pathlib import Path

# Match each rule only against languages it is intended to analyze.
RULES = (
    ('PY-EVAL', 'high', re.compile(r'\b(?:eval|exec)\s*\('),
     'Dynamic Python execution', frozenset({'.py'})),
    ('PY-SHELL', 'high', re.compile(r'\bshell\s*=\s*True\b'),
     'Shell execution enabled', frozenset({'.py'})),
    ('WEB-INNERHTML', 'medium', re.compile(r'\.innerHTML\s*='),
     'Review DOM HTML insertion', frozenset({'.js', '.ts', '.jsx', '.tsx'})),
)
EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx'}
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
    """Blank Python strings and comments, preserving original line numbers.

    This is a lexical filter, not an AST or semantic security analysis.
    Syntax errors do not stop scanning content tokenized before the error.
    """
    lines = [list(line) for line in source.splitlines(keepends=True)]
    literal_tokens = {tokenize.STRING, tokenize.COMMENT, getattr(tokenize, 'FSTRING_MIDDLE', -1)}
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type not in literal_tokens:
                continue
            (start_line, start_col), (end_line, end_col) = token.start, token.end
            for index in range(start_line - 1, end_line):
                if index >= len(lines):
                    break
                left = start_col if index == start_line - 1 else 0
                right = end_col if index == end_line - 1 else len(lines[index])
                for column in range(left, min(right, len(lines[index]))):
                    if lines[index][column] not in '\r\n':
                        lines[index][column] = ' '
    except (tokenize.TokenError, IndentationError):
        pass
    return ''.join(''.join(line) for line in lines)


def python_call_findings(source: str) -> set[tuple[int, str]] | None:
    """Find executable Python calls, including those in f-string expressions.

    AST is used only for valid Python. On syntax errors the lexical scanner
    remains a best-effort fallback; the source is never imported or executed.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return None
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            callable_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callable_name = node.func.attr
        else:
            callable_name = None
        if callable_name in ('eval', 'exec'):
            found.add((node.lineno, 'PY-EVAL'))
        if any(
            keyword.arg == 'shell'
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            found.add((node.lineno, 'PY-SHELL'))
    return found

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
            try:
                if file.stat().st_size > MAX_FILE_BYTES:
                    continue
                source = file.read_text(encoding='utf-8')
            except (OSError, UnicodeDecodeError):
                continue

            extension = file.suffix.lower()
            relative = file.relative_to(root).as_posix()
            # A valid Python AST is authoritative: regexes would otherwise
            # flag harmless assignments and function declarations.
            if extension == '.py':
                calls = python_call_findings(source)
                if calls is not None:
                    python_rules = {
                        rule: (level, message)
                        for rule, level, _, message, _ in RULES
                    }
                    for line_number, rule_id in sorted(calls):
                        severity, message = python_rules[rule_id]
                        findings.append({
                            'file': relative, 'line': line_number, 'rule': rule_id,
                            'severity': severity, 'message': message,
                        })
                    continue

            # Syntax-invalid Python still gets a best-effort lexical scan.
            # JavaScript/TypeScript always use the documented regex heuristic.
            inspected = mask_python_literals(source) if extension == '.py' else source
            for line_number, line in enumerate(inspected.splitlines(), 1):
                for rule_id, severity, pattern, message, extensions in RULES:
                    if extension in extensions and pattern.search(line):
                        findings.append({
                            'file': relative, 'line': line_number, 'rule': rule_id,
                            'severity': severity, 'message': message,
                        })
    return sorted(findings, key=lambda item: (item['file'], item['line'], item['rule']))

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
