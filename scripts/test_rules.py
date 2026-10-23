#!/usr/bin/env python3
"""Run exact ID/line regression assertions against the real scanner.

Fixtures are static input, never executed. Every target must be scanned unless a
case explicitly asserts path exclusion with expect_scanned=false and skip_reason;
engine errors, timeout, invalid JSON, unexpected matches and missing matches fail.
"""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import yaml
from rule_yaml import load as load_yaml

REPO = Path(__file__).resolve().parents[1]

def run_group(key, cases, engine, work):
    pack, rule_file, rule_ids = key
    config_source = REPO / 'packs' / pack / rule_file
    doc = load_yaml(config_source.read_text())
    rules = [r for r in doc['rules'] if r['id'] in rule_ids]
    if {r['id'] for r in rules} != set(rule_ids):
        raise ValueError(f'Rule selection does not exist: {key}')
    group = Path(tempfile.mkdtemp(prefix='group-', dir=work))
    config = group / 'selected.yaml'
    config.write_text(yaml.safe_dump({'rules': rules}, sort_keys=False, allow_unicode=True))
    targets = group / 'targets'
    targets.mkdir()
    paths = {}
    for idx, case in enumerate(cases):
        relative = Path(case['filename'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError(f'Unsafe fixture filename: {relative}')
        p = targets / f'case-{idx}' / relative
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(case['code'])
        paths[str(p.resolve())] = case
    state = group / 'state'
    state.mkdir()
    env = os.environ.copy()
    env.setdefault('XDG_CACHE_HOME', str(REPO / '.build' / 'cache'))
    for prefix in ('SEMGREP', 'OPENGREP'):
        env[prefix + '_LOG_FILE'] = str(state / (prefix.lower() + '.log'))
        env[prefix + '_SETTINGS_FILE'] = str(state / 'settings.yaml')
    env['SEMGREP_SEND_METRICS'] = 'off'
    cmd = [engine, 'scan', '--config', str(config), '--json', '--strict',
           '--disable-version-check', '--no-git-ignore', '--no-rewrite-rule-ids',
           '--jobs', '1', str(targets)]
    try:
        result = subprocess.run(cmd, cwd=REPO, env=env, capture_output=True,
                                text=True, timeout=90)
    except subprocess.TimeoutExpired as exc:
        return [{'name': c['name'], 'pass': False, 'reason': 'scanner timeout'} for c in cases]
    (group / 'result.json').write_text(result.stdout)
    (group / 'stderr.txt').write_text(result.stderr)
    (group / 'command.json').write_text(json.dumps(cmd))
    try:
        data = json.loads(result.stdout)
    except ValueError:
        return [{'name': c['name'], 'pass': False, 'reason': 'invalid scanner JSON',
                 'exit': result.returncode, 'artifact': str(group)} for c in cases]
    errors = data.get('errors', [])
    required_version = json.loads((REPO / 'release-config.json').read_text())['engines']['opengrep']
    if data.get('version') != required_version:
        errors = errors + [{'type': 'EngineVersionMismatch', 'expected': required_version, 'actual': data.get('version')}]
    scanned = {str(Path(p).resolve()) for p in data.get('paths', {}).get('scanned', [])}
    actual = defaultdict(Counter)
    for finding in data.get('results', []):
        actual[str(Path(finding['path']).resolve())][(finding['check_id'], finding['start']['line'])] += 1
    records = []
    for path, case in paths.items():
        expected = Counter((f['id'], f['line']) for f in case['expect'])
        found = actual[path]
        expect_scanned = case.get('expect_scanned', True)
        if not expect_scanned and (expected or not case.get('skip_reason')):
            raise ValueError('Path-exclusion case needs skip_reason and no expected findings')
        ok = result.returncode == 0 and not errors and ((path in scanned) == expect_scanned) and expected == found
        records.append({'name': case['name'], 'pack': pack, 'rule_ids': list(rule_ids),
                        'pass': ok, 'exit': result.returncode, 'engine_version': data.get('version'), 'scanned': path in scanned,
                        'expect_scanned': expect_scanned, 'skip_reason': case.get('skip_reason'),
                        'expected': [{'id': k[0], 'line': k[1], 'count': v} for k,v in sorted(expected.items())],
                        'actual': [{'id': k[0], 'line': k[1], 'count': v} for k,v in sorted(found.items())],
                        'errors': errors, 'artifact': str(group)})
    return records

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', default=os.environ.get('OPENGREP_BIN', shutil.which('opengrep')))
    parser.add_argument('--suite', action='append', help='JSON filename/stem; repeat to select suites')
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--output', default=str(REPO / '.build' / 'regression-results.json'))
    args = parser.parse_args()
    if not args.engine:
        parser.error('Install the pinned engine or set OPENGREP_BIN / --engine')
    engine = str(Path(args.engine).resolve())
    if not Path(engine).is_file():parser.error(f'Engine not found: {engine}')
    files = sorted((REPO / 'tests' / 'regression').glob('*.json'))
    if args.suite:
        wanted = set(args.suite)
        files = [p for p in files if p.name in wanted or p.stem in wanted]
        matched = {x for x in wanted if any(p.name == x or p.stem == x for p in files)}
        if wanted != matched:parser.error(f'Unknown suites: {wanted-matched}')
    groups = defaultdict(list)
    names = set()
    for p in files:
        cases = json.loads(p.read_text())
        if not isinstance(cases, list):raise ValueError(f'{p}: expected list')
        for c in cases:
            if c['name'] in names:raise ValueError(f'Duplicate case: {c["name"]}')
            names.add(c['name'])
            groups[(c['pack'], c['rule_file'], tuple(sorted(c['rule_ids'])))].append(c)
    if not names:parser.error('No test cases selected')
    work = REPO / '.build' / 'regression'
    work.mkdir(parents=True, exist_ok=True)
    output = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.jobs, 4))) as pool:
        futures = {pool.submit(run_group, k, cs, engine, work): k for k,cs in groups.items()}
        for f in as_completed(futures):
            try:
                records = f.result()
            except Exception as exc:
                records = [{'name': c['name'], 'pass': False, 'reason': f'{type(exc).__name__}: {exc}'}
                           for c in groups[futures[f]]]
            output.extend(records)
            for r in records:
                print(('PASS ' if r['pass'] else 'FAIL ') + r['name'], flush=True)
    output.sort(key=lambda r:r['name'])
    dest = Path(args.output);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps({'engine': engine, 'total': len(output),
                               'passed': sum(r['pass'] for r in output), 'cases': output}, indent=2))
    failures = sum(not r['pass'] for r in output)
    print(f'{len(output)-failures}/{len(output)} cases passed; {failures} failed. Results: {dest}')
    return bool(failures)

if __name__ == '__main__':
    sys.exit(main())
