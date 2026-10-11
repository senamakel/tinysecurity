#!/usr/bin/env python3
"""Enforce native Windows file and changed-line coverage without dependencies.

JSON supplies per-file executable counts; LCOV supplies changed executable lines.
Only exact checkout-relative crate paths are admitted. Both Windows audit sources
must be instrumented; changes to either require measured changed lines.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REQUIRED = (
    'crates/tinysecurity-audit/src/windows.rs',
    'crates/tinysecurity-audit/src/windows_acl.rs',
)


def relative_source(filename, root):
    """Return a crate path under the exact checkout, or None for other files."""
    filename = filename.replace('\\', '/')
    root = root.replace('\\', '/').rstrip('/')
    # Windows drive paths are case insensitive; POSIX paths are not.
    windows = bool(re.match(r'^[A-Za-z]:/', root))
    candidate = filename.casefold() if windows else filename
    prefix = (root.casefold() if windows else root) + '/'
    if not candidate.startswith(prefix):
        return None
    relative = filename[len(prefix):]
    if windows:
        relative = relative.casefold()
    parts = relative.split('/')
    if any(part in ('', '.', '..') for part in parts):
        return None
    if not relative.startswith('crates/') or not relative.endswith('.rs'):
        return None
    return relative


def check_files(report, root, minimum):
    """Reject absent, empty, inconsistent, or below-threshold source reports."""
    files = {}
    for datum in report['data']:
        for entry in datum['files']:
            name = relative_source(entry['filename'], root)
            if name is None:
                continue
            lines = entry['summary']['lines']
            count, covered = lines['count'], lines['covered']
            if (type(count) is not int or type(covered) is not int
                    or count < 0 or covered < 0 or covered > count):
                raise ValueError(f'invalid executable counts: {name}')
            counts = (covered, count)
            if name in files and files[name] != counts:
                raise ValueError(f'conflicting duplicate source: {name}')
            files[name] = counts
    for name in REQUIRED:
        if name not in files:
            raise ValueError(f'missing required Windows source: {name}')
        if files[name][1] == 0:
            raise ValueError(f'no executable lines in required Windows source: {name}')
    for name, (covered, count) in sorted(files.items()):
        if count and covered * 100 < minimum * count:
            raise ValueError(f'{name}: {covered}/{count} lines below {minimum}%')
    return files


def parse_lcov(report, root):
    """Normalize LCOV SF records and merge repeated instrumentation counts."""
    files = {}
    current = None
    for record in report.splitlines():
        if record.startswith('SF:'):
            current = relative_source(record[3:], root)
            if current is not None:
                files.setdefault(current, {})
        elif record.startswith('DA:') and current is not None:
            fields = record[3:].split(',')
            line, count = int(fields[0]), int(fields[1])
            if line <= 0 or count < 0:
                raise ValueError(f'invalid LCOV line: {current}')
            files[current][line] = files[current].get(line, 0) + count
        elif record == 'end_of_record':
            current = None
    return files


def production_source(name):
    """Tests are not production changes; their JSON file coverage still applies."""
    return (name.startswith('crates/') and '/src/' in name
            and name.endswith('.rs') and not name.endswith('_tests.rs'))


def changed_lines(diff):
    """Extract added/modified production line ranges from git's unified=0 diff."""
    files = {}
    current = None
    for line in diff.splitlines():
        if line.startswith('+++ '):
            name = line[4:]
            if not name.startswith('b/') and name != '/dev/null':
                raise ValueError('unrecognized git diff source path')
            current = name[2:] if name.startswith('b/') else None
            if current is not None and any(part in ('', '.', '..') for part in current.split('/')):
                raise ValueError('invalid git diff source path')
            if current is not None and not production_source(current):
                current = None
        elif current is not None and line.startswith('@@ '):
            match = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', line)
            if match is None:
                raise ValueError('invalid git diff hunk')
            first = int(match[1])
            count = int(match[2]) if match[2] is not None else 1
            if count:
                files.setdefault(current, set()).update(range(first, first + count))
    return files


def check_changed(lines, changed, minimum):
    """Require measured Windows changes and a nonzero changed-line denominator."""
    for name in REQUIRED:
        if not lines.get(name):
            raise ValueError(f'no measured changed or executable LCOV lines: {name}')
    if not changed:
        return None
    for name in REQUIRED:
        if name not in changed:
            continue
        measured = set(lines.get(name, {})) & changed.get(name, set())
        if not measured:
            raise ValueError(f'no measured changed executable lines: {name}')
    covered = total = 0
    for name, changed_set in changed.items():
        for line in changed_set & set(lines.get(name, {})):
            total += 1
            covered += lines[name][line] > 0
    if not total:
        raise ValueError('no measured changed executable lines in workspace')
    if covered * 100 < minimum * total:
        raise ValueError(f'changed lines: {covered}/{total} below {minimum}%')
    return covered, total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', required=True)
    parser.add_argument('--lcov', required=True)
    parser.add_argument('--base', required=True, help='canonical PR base commit/ref')
    parser.add_argument('--root', default=str(Path.cwd()))
    args = parser.parse_args()
    files = check_files(json.loads(Path(args.json).read_text(encoding='utf-8')), args.root, 90)
    print('File\tLine coverage\tCovered lines\tCoverable lines')
    for name, (covered, count) in sorted(files.items()):
        if count:
            print(f'{name}\t{covered * 100 / count:.2f}%\t{covered}\t{count}')
    diff = subprocess.run(
        ['git', '-c', 'core.quotePath=false', 'diff', '--no-ext-diff', '--no-renames',
         '--unified=0', args.base, 'HEAD', '--', 'crates/'],
        cwd=args.root, check=True, text=True, capture_output=True,
    ).stdout
    changed = changed_lines(diff)
    lcov = parse_lcov(Path(args.lcov).read_text(encoding='utf-8'), args.root)
    result = check_changed(lcov, changed, 80)
    if result is None:
        print('No changed production Rust lines relative to canonical base; file gate passed.')
        return
    covered, total = result
    print(f'Changed executable lines: {covered}/{total} ({covered * 100 / total:.2f}%)')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as summary:
            summary.write(f'Native Windows coverage: {len(files)} source reports; '
                          f'changed executable lines {covered}/{total}.\n')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f'native coverage rejected: {error}', file=sys.stderr)
        sys.exit(1)
