#!/usr/bin/env python3
"""Exercise the gate's failure paths without running or replacing domain logic."""
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

repository = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    (root / 'src').mkdir()
    (root / 'docs').mkdir()
    for name in ('matching.rs', 'model.rs'):
        (root / 'src' / name).write_text((repository / 'src' / name).read_text())
    exclusions = (repository / 'docs/coverage-exclusions.json').read_text()
    (root / 'docs/coverage-exclusions.json').write_text(exclusions)
    anchor = json.loads(exclusions)[0]['line']
    records = []
    files = []
    for name, line_count, branch_count, counters in [
        ('matching.rs', 2, 2, f'DA:1,1\nDA:{anchor},0\nBRDA:1,0,0,1\nBRDA:1,0,1,1\n'),
        ('model.rs', 1, 0, 'DA:1,1\n'),
    ]:
        source = str(root / 'src' / name)
        covered = line_count - (name == 'matching.rs')
        records.append(f'SF:{source}\n{counters}LF:{line_count}\nLH:{covered}\n'
                       f'BRF:{branch_count}\nBRH:{branch_count}\nend_of_record\n')
        files.append({'filename': source, 'branches': [[1, 1, 1, 2]] if branch_count else [], 'summary': {
            'lines': {'count': line_count, 'covered': covered},
            'branches': {'count': branch_count, 'covered': branch_count},
        }})
    annotated = (f'{root / "src/matching.rs"}:\n1| 1| line\n{anchor}| 0| line\n'
                 f'{root / "src/model.rs"}:\n1| 1| line\n')
    (root / 'coverage.txt').write_text(annotated)
    report = {'type': 'llvm.coverage.json.export', 'data': [{'files': files}]}
    valid = ''.join(records)
    cases = [
        ('complete', valid, report, True),
        ('missing file', records[0], report, False),
        ('deleted measured line', valid.replace('DA:1,1\n', '', 1), report, False),
        ('missing final terminator', valid.rsplit('end_of_record', 1)[0], report, False),
        ('nested source', valid.replace('end_of_record\n', '', 1), report, False),
        ('duplicate file', valid + records[0], report, False),
        ('duplicate line', valid.replace('DA:1,1\n', 'DA:1,1\nDA:1,1\n', 1), report, False),
        ('duplicate summary', valid.replace('LF:2\n', 'LF:2\nLF:2\n'), report, False),
        ('missing summary', valid.replace('LF:2\n', ''), report, False),
        ('missing branch', valid.replace('BRDA:1,0,0,1\n', ''), report, False),
        ('unknown branch', valid.replace('BRDA:1,0,0,1', 'BRDA:1,0,0,-'), report, False),
        ('uncovered branch', valid.replace('BRDA:1,0,0,1', 'BRDA:1,0,0,0'), report, False),
        ('uncovered line', valid.replace('DA:1,1', 'DA:1,0'), report, False),
        ('no excluded anchor', valid.replace(f'DA:{anchor},0\n', ''), report, False),
        ('nonproduction source', valid.replace('/src/model.rs', '/tests/model.rs'), report, False),
        ('empty data', valid, {'type': report['type'], 'data': []}, False),
    ]
    duplicate = copy.deepcopy(report)
    duplicate['data'][0]['files'].append(files[0])
    cases.append(('duplicate companion file', valid, duplicate, False))
    for name, lcov, companion, accepted in cases:
        (root / 'coverage.lcov').write_text(lcov)
        (root / 'coverage.json').write_text(json.dumps(companion))
        result = subprocess.run(
            [sys.executable, str(repository / '.github/check-coverage.py'),
             'coverage.lcov', 'coverage.json', 'coverage.txt'], cwd=root, capture_output=True, text=True,
            check=False,
        )
        if (result.returncode == 0) != accepted:
            raise SystemExit(f'{name}: unexpected result\n{result.stdout}{result.stderr}')
    print(f'Coverage report integrity: {len(cases)} cases passed')
