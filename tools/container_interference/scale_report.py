#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Matched-window S6 report; missing samples and late attachment fail closed."""
import argparse
import collections
import json
import pathlib
import re
import statistics
from overhead import interval
from scale_plan import matrix

VALUES = re.compile(r'(\w+)=([^ ]+)')
CASE = re.compile(r'scale-(ambient|diagnostic)-(1|12|24|48)-(\d+)-(bench|open-loop)-(off|ip|diag)\.log')
BAD = {'capture_failure', 'budget_disable', 'capture_error', 'sample_schema_error',
       'metrics_budget_disable', 'budget_unavailable', 'buffer_loss', 'entry_budget_disable'}


def analyze(text):
    cases, observers, values, diag = {}, {}, {}, {}
    roots, samples = collections.defaultdict(dict), collections.defaultdict(collections.Counter)
    failures, errors = [], []
    current = observer = None
    for line in text.splitlines():
        if line.startswith('CIS_FILE '):
            m = CASE.search(line)
            current = (m[1], int(m[2]), int(m[3]), m[4], m[5]) if m else None
            m = re.search(r'observer-(\d+)\.jsonl', line)
            observer = int(m[1]) if m else None
        if current and line.startswith('CIS_FLEET_BEGIN '):
            f = dict(VALUES.findall(line))
            if current in cases:
                failures.append({'case': current, 'reason': 'duplicate case, no last-write-wins selection'})
            cases[current] = f
            if current[4] != 'off':
                observers[int(f['observer_pid'])] = current
        if current and line.startswith(('CIS_RESULT ', 'CIS_LATENCY ')):
            f = dict(VALUES.findall(line))
            slot = int(f['cgroup'].rsplit('-', 1)[1])
            if (*current, slot) in values:
                failures.append({'case': current, 'reason': 'duplicate container observation', 'slot': slot})
            values[(*current, slot)] = f
            if int(f.get('errors', 0)) or int(f.get('timeouts', 0)):
                failures.append({'case': current, 'reason': 'workload error/timeout', 'slot': slot})
        if 'CIS_FLEET_END result=FAIL' in line or 'CIS_S6_FAILURES=1' in line:
            failures.append({'case': current, 'reason': line})
        if not line.startswith('{'):
            continue
        try:
            e = json.loads(line)
        except ValueError:
            errors.append({'reason': 'invalid_json'})
            continue
        case = observers.get(observer)
        if not case:
            continue
        kind = e.get('kind')
        f = dict(VALUES.findall(e.get('detail', '')))
        if kind == 'register':
            roots[case][e['id']] = e.get('name')
        if kind == 'IP':
            begin = int(cases[case]['start_ns'])
            if begin <= int(f['sample_time_ns']) < begin+int(cases[case]['duration'])*10**9:
                samples[case][e['id']] += 1
        if kind == 'diagnostic_start':
            diag[case] = f
        if kind in BAD or (kind in ('budget', 'final_quality') and
                           (int(f.get('errors', 0)) or int(f.get('drops', 0)))):
            errors.append({'case': case, 'event': e})
        if kind == 'perf_quality' and (int(f.get('lost', 0)) or int(f.get('invalid_records', 0))):
            errors.append({'case': case, 'event': e})
    expected = {(x['family'], x['count'], x['round'], x['workload'], x['mode']) for x in matrix()}
    if set(cases) != expected:
        failures.append({'reason': 'incomplete/unexpected matrix', 'missing': sorted(expected-set(cases)),
                         'unexpected': sorted(set(cases)-expected)})
    missing = []
    for case in expected:
        if any((*case, i) not in values for i in range(case[1])):
            failures.append({'case': case, 'reason': 'missing container observations'})
        if case[4] != 'off' and (len(roots[case]) != case[1] or
                                any(not samples[case][r] for r in roots[case])):
            missing.append({'case': case, 'registered': len(roots[case]), 'sampled': dict(samples[case])})
        if case[4] == 'diag' and case in cases:
            start = int(cases[case]['start_ns'])
            d = diag.get(case, {})
            if (int(d.get('start_ns', -1)) != start or int(d.get('deadline_ns', -1)) != start+2*10**9 or
                    not 0 < int(d.get('ready_ns', 0)) < start):
                failures.append({'case': case, 'reason': 'full 2-second window not armed before measurement'})
    results = []
    for count in (1, 12, 24, 48):
        for family, modes in (('ambient', ('ip',)), ('diagnostic', ('ip', 'diag'))):
            for workload in ('bench', 'open-loop'):
                for mode in modes:
                    for role in ('target', 'bystander') if count>1 else ('target',):
                        pairs, absolute = [], []
                        for run in range(1, 6):
                            slot = (run+(role == 'bystander')) % count
                            base = values.get((family, count, run, workload, 'off', slot))
                            measured = values.get((family, count, run, workload, mode, slot))
                            if not base or not measured:
                                continue
                            if workload == 'bench':
                                # A full final batch may straddle the deadline. Bound it against the monitor.
                                seconds = 15 if family == 'ambient' else 2
                                b = int(base['operations'])/seconds
                                x = max(0, int(measured['operations'])-int(measured.get('last_batch_ops', 256)))/seconds
                                delta = (1-x/b)*100
                            else:
                                b, x = int(base['p99_ns']), int(measured['p99_ns'])
                                delta = (x/b-1)*100
                            pairs.append(delta); absolute.append(x-b)
                        threshold = 2 if workload == 'open-loop' else 3 if family == 'diagnostic' else 1
                        ci = interval(pairs) if pairs else [None, None]
                        status = 'BLOCKED' if len(pairs) != 5 or ci[1] is None else 'PASS' if ci[1] <= threshold else 'FAIL' if ci[0] > threshold else 'BLOCKED'
                        results.append({'containers': count, 'family': family, 'workload': workload, 'mode': mode,
                                        'role': role, 'n': len(pairs), 'degradation_percent': pairs,
                                        'mean_percent': statistics.mean(pairs) if pairs else None,
                                        'mean_absolute_change': statistics.mean(absolute) if absolute else None,
                                        '95pct_interval': ci, 'threshold_percent': threshold, 'status': status})
    valid = not failures and not errors and not missing
    return {'version': 1, 'scope': 'isolated ARM64 KVM only', 'case_count': len(cases), 'results': results,
            'failures': failures, 'observer_errors': errors, 'missing_coverage': missing, 'coverage_valid': valid,
            'pass': valid and all(r['status']=='PASS' for r in results if r['family']=='ambient' or r['workload']=='bench'),
            'limitations': ['Final bench batch is conservatively charged against the monitored configuration.',
                           'Diagnostic P99 is reported, not silently admitted under the ambient gate.',
                           '128/256 idle and background resource gates require their separate verified reports.']}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('input', type=pathlib.Path); p.add_argument('output', type=pathlib.Path)
    a = p.parse_args(); result = analyze(a.input.read_text())
    with a.output.open('x') as f:
        json.dump(result, f, indent=2)
    print(json.dumps({'pass': result['pass'], 'case_count': result['case_count'], 'failures': len(result['failures'])}))
    raise SystemExit(0 if result['pass'] else 1)
