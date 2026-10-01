#!/usr/bin/env python3
"""Require every emitted production source line and branch in LLVM LCOV."""
import json
import sys
from pathlib import Path

root = Path.cwd().resolve()
exclusions = json.loads((root / 'docs/coverage-exclusions.json').read_text())
allowed = {}
for item in exclusions:
    path = item['path']
    line = item['line']
    source = (root / path).read_text().splitlines()
    if not item['reason'] or source[line - 1].strip() != item['source']:
        raise SystemExit('Coverage exclusion no longer matches reviewed source')
    allowed[path, line] = item['reason']

def relative_source(filename):
    path = str(Path(filename).resolve().relative_to(root))
    if not path.startswith('src/'):
        raise SystemExit('Unexpected production source in coverage report')
    return path


report = json.loads(Path(sys.argv[2]).read_text())
if report.get('type') != 'llvm.coverage.json.export' or len(report.get('data', [])) != 1:
    raise SystemExit('Missing or ambiguous companion LLVM coverage data')
expected = {}
for item in report['data'][0]['files']:
    path = relative_source(item['filename'])
    if path in expected:
        raise SystemExit('Duplicate companion source file')
    summary = item['summary']
    expected[path] = {
        'LF': summary['lines']['count'],
        'LH': summary['lines']['covered'],
        'BRF': summary['branches']['count'],
        'BRH': summary['branches']['covered'],
    }
if not expected:
    raise SystemExit('Missing companion production files')

lines = {}
branches = {}
finished = set()
source = None
summary = {}
for row in Path(sys.argv[1]).read_text().splitlines():
    if row.startswith('SF:'):
        if source is not None:
            raise SystemExit('Unterminated source coverage record')
        source = relative_source(row[3:])
        if source in finished or source not in expected:
            raise SystemExit('Duplicate or unexpected source coverage record')
        summary = {}
    elif row.startswith('DA:'):
        number, count, *_ = row[3:].split(',')
        key = (source, int(number))
        if source is None or key in lines or int(count) < 0:
            raise SystemExit('Invalid or duplicate line coverage record')
        lines[key] = int(count)
    elif row.startswith('BRDA:'):
        number, block, branch, count = row[5:].split(',')
        key = (source, int(number), block, branch)
        if source is None or key in branches or (count != '-' and int(count) < 0):
            raise SystemExit('Invalid or duplicate branch coverage record')
        branches[key] = 0 if count == '-' else int(count)
    elif row.startswith(('LF:', 'LH:', 'BRF:', 'BRH:')):
        metric, count = row.split(':')
        if source is None or metric in summary or int(count) < 0:
            raise SystemExit('Invalid or duplicate source coverage summary')
        summary[metric] = int(count)
    elif row == 'end_of_record':
        if source is None or summary != expected[source]:
            raise SystemExit('Incomplete or inconsistent source coverage record')
        measured_branches = [count for key, count in branches.items() if key[0] == source]
        if (len(measured_branches) != summary['BRF']
                or sum(count > 0 for count in measured_branches) != summary['BRH']
                or not any(key[0] == source for key in lines)):
            raise SystemExit('Missing source counters')
        finished.add(source)
        source = None

if source is not None or finished != expected.keys():
    raise SystemExit('Truncated report or missing production source files')
if not lines or not branches or not allowed.keys() <= lines.keys():
    raise SystemExit('Missing measured production coverage or exclusion anchor')
if any((key[0], key[1]) in allowed for key in branches):
    raise SystemExit('A line-only exclusion unexpectedly contains a branch')
measured = {key: count for key, count in lines.items() if key not in allowed}
missing_lines = [key for key, count in measured.items() if count == 0]
missing_branches = [key for key, count in branches.items() if count == 0]
print(f'lines: {len(measured) - len(missing_lines)}/{len(measured)}; exclusions: {len(allowed)}')
print(f'branches: {len(branches) - len(missing_branches)}/{len(branches)}')
if missing_lines or missing_branches:
    print('Uncovered source lines:', missing_lines)
    print('Uncovered source branches:', missing_branches)
    raise SystemExit('Require 100% emitted production source lines and branches')
