"""Bounded, read-only static text scanner; heuristic findings, not proof of exploits."""
from __future__ import annotations
import argparse
import ast
import io
import json
import os
import re
import stat
import tokenize
from pathlib import Path

# Match each rule only against languages it is intended to analyze.
RULES = (
    ('PY-EVAL', 'high', re.compile(r'\b(?:eval|exec)\s*\('),
     'Dynamic Python execution', frozenset({'.py'})),
    ('PY-SHELL', 'high', re.compile(r'\bshell\s*=\s*True\b'),
     'Shell execution enabled', frozenset({'.py'})),
    ('PY-OS-SYSTEM', 'high', re.compile(r'\bos\.system\s*\('),
     'Direct shell command execution', frozenset({'.py'})),
    ('WEB-INNERHTML', 'medium', re.compile(r'\.innerHTML\s*='),
     'Review DOM HTML insertion', frozenset({'.js', '.ts', '.jsx', '.tsx'})),
)
EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx'}
SKIP = {'.git', 'node_modules', '.venv', 'dist', 'build', '__pycache__'}
MAX_FILE_BYTES = 256_000
INCOMPLETE_SCAN_RULE = 'SCAN-INCOMPLETE'


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
    os_aliases = {'os'}
    system_aliases = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            os_aliases.update(alias.asname or 'os' for alias in node.names if alias.name == 'os')
        elif isinstance(node, ast.ImportFrom) and node.module == 'os':
            system_aliases.update(
                alias.asname or 'system' for alias in node.names if alias.name == 'system'
            )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            callable_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callable_name = node.func.attr
        else:
            callable_name = None
        if isinstance(node.func, ast.Name) and callable_name in ('eval', 'exec'):
            found.add((node.lineno, 'PY-EVAL'))
        if (
            (isinstance(node.func, ast.Attribute)
             and node.func.attr == 'system'
             and isinstance(node.func.value, ast.Name)
             and node.func.value.id in os_aliases)
            or (isinstance(node.func, ast.Name) and node.func.id in system_aliases)
        ):
            found.add((node.lineno, 'PY-OS-SYSTEM'))
        if any(
            keyword.arg == 'shell'
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            found.add((node.lineno, 'PY-SHELL'))
    return found


def incomplete_finding(root: Path, path: str | os.PathLike, message: str) -> dict:
    """Represent an unscanned source path as a high-severity finding."""
    candidate = Path(path)
    try:
        relative = candidate.resolve(strict=False).relative_to(root).as_posix()
    except (OSError, ValueError):
        relative = candidate.name or '.'
    return {
        'file': relative,
        'line': 1,
        'rule': INCOMPLETE_SCAN_RULE,
        'severity': 'high',
        'message': message,
    }


def scan(root: Path, exclude: set[str] | None = None) -> list[dict]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError('Scan root must be an existing directory')
    if exclude is not None and any(
        not isinstance(name, str) or not name or name in {'.', '..'}
        or '/' in name or '\\' in name for name in exclude
    ):
        raise ValueError('Exclude entries must be plain directory names')
    skipped = SKIP | (exclude or set())
    findings = []

    def on_walk_error(error: OSError) -> None:
        findings.append(incomplete_finding(
            root, error.filename or root,
            'Directory could not be traversed; scan is incomplete',
        ))

    # Prune excluded directories before traversal. Path.rglob() would still
    # enumerate every nested file inside node_modules/.venv/dist/build.
    for directory, dirnames, filenames in os.walk(
        root, topdown=True, onerror=on_walk_error, followlinks=False
    ):
        current = Path(directory)
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in skipped and not (current / name).is_symlink()
        )

        for filename in sorted(filenames):
            file = current / filename
            if file.suffix.lower() not in EXTENSIONS or file.is_symlink():
                continue
            relative = file.relative_to(root).as_posix()
            try:
                if not file.is_file():
                    findings.append(incomplete_finding(
                        root, file, 'Source path is not a regular file; scan is incomplete'
                    ))
                    continue

                # O_NOFOLLOW prevents a symlink swap where supported; O_NONBLOCK
                # prevents special files such as FIFOs from blocking the scan.
                flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
                descriptor = os.open(file, flags)
                with os.fdopen(descriptor, 'rb') as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        findings.append(incomplete_finding(
                            root, file, 'Source path is not a regular file; scan is incomplete'
                        ))
                        continue
                    raw = stream.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    findings.append(incomplete_finding(
                        root, file, 'File exceeds 256 KB and was not scanned'
                    ))
                    continue
                source = raw.decode('utf-8')
            except UnicodeDecodeError:
                findings.append(incomplete_finding(
                    root, file, 'Source file is not valid UTF-8 and was not scanned'
                ))
                continue
            except OSError:
                findings.append(incomplete_finding(
                    root, file, 'Source file could not be read; scan is incomplete'
                ))
                continue

            extension = file.suffix.lower()
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
    # A partial scan is never considered clean, even with --fail-on none.
    if any(item['rule'] == INCOMPLETE_SCAN_RULE for item in findings):
        return 2
    severities = {'high': 2, 'medium': 1}
    thresholds = {'high': 2, 'medium': 1, 'none': 3}
    return 1 if any(severities[x['severity']] >= thresholds[args.fail_on] for x in findings) else 0


if __name__ == '__main__':
    raise SystemExit(main())
