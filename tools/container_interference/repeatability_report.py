# SPDX-License-Identifier: GPL-2.0
"""Independent OFF/OFF calibration; never grants observer admission."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import statistics

from session_check import extract, numbers

PROTOCOL = dict(schema='cis-repeatability-v1', boots=2, pairs_per_boot=5,
                window_ms=2000, arrival_rate=2000, warmup_operations=4096,
                timer_slack='inherited_default', tracing=False, collectors=False,
                throughput_equivalence_pct=1, latency_equivalence_pct=2,
                scope='two containers, fixed KVM layout; calibration only')


def interval(values):
    n = len(values)
    if n not in (5, 10):
        raise ValueError('five pairs per boot or ten pooled pairs required')
    half = {5: 2.776445105, 10: 2.262157163}[n] * statistics.stdev(values) / n**.5
    mean = statistics.mean(values)
    return dict(n=n, mean_pct=mean, lower95_pct=mean-half, upper95_pct=mean+half,
                pairs_pct=values)


def one(lines, prefix):
    found = [numbers(line) for line in lines if line.startswith(prefix)]
    if len(found) != 1:
        raise ValueError('exactly one '+prefix+' required')
    return found[0]


def analyze(artifacts):
    if len(artifacts) != 2:
        raise ValueError('two independent boot logs required')
    seen_boots, ids, sources, data, evidence = set(), set(), [], {}, []
    for name, raw in artifacts:
        text = raw.decode('utf-8', errors='strict')
        headers = [json.loads(x.split(' ', 1)[1]) for x in text.splitlines()
                   if x.startswith('CIS_REPEATABILITY_PLAN ')]
        if len(headers) != 1:
            raise ValueError('one frozen plan per boot required')
        plan = headers[0]
        if plan.get('protocol') != PROTOCOL:
            raise ValueError('protocol differs from frozen calibration')
        boot = plan.get('boot_index')
        if type(boot) is not int or boot not in (0, 1) or boot in seen_boots:
            raise ValueError('duplicate/invalid boot')
        boot_id = plan.get('boot_id')
        if not isinstance(boot_id, str) or not re.fullmatch('[0-9a-f-]{36}', boot_id) or boot_id in ids:
            raise ValueError('independent boot IDs required')
        seen_boots.add(boot); ids.add(boot_id)
        source = plan.get('source')
        if not isinstance(source, dict) or set(source) != {'workload_sha256', 'launcher_sha256', 'kernel_notes_sha256', 'cmdline_sha256', 'runner_sha256'} or any(not re.fullmatch('[0-9a-f]{64}', str(v)) for v in source.values()):
            raise ValueError('source manifest missing')
        sources.append(source)
        if text.splitlines().count('CIS_REPEATABILITY_DONE=0') != 1 or text.splitlines().count('CIS_PROFILE_VM_EXIT=0') != 1:
            raise ValueError('complete successful VM required; no partial pair selection')
        cases = [json.loads(x.split(' ', 1)[1]) for x in text.splitlines() if x.startswith('CIS_REPEATABILITY_CASE ')]
        required = {(w, p, label, role) for w in ('throughput', 'latency')
                    for p in range(5) for label in ('A', 'B') for role in range(2)}
        files = extract(text); seen = set(); sequence = []
        for case in cases:
            key = (case['workload'], case['pair'], case['label'], case['role'])
            if key in seen or key not in required or case.get('exit_code') != 0:
                raise ValueError('missing/duplicate/failed cell')
            seen.add(key); sequence.append(key)
            w, p, label, role = key
            if case.get('cpu') != ((role ^ ((boot*5+p) % 2))*2):
                raise ValueError('role/CPU rotation differs')
            path = case.get('path')
            if path not in files:
                raise ValueError('raw workload absent')
            lines = files[path].splitlines()
            if any(x.startswith(('CIS_LATENCY_SAMPLE ', 'CIS_LATENCY_TIMELINE ')) for x in lines):
                raise ValueError('traced calibration rejected')
            warm = one(lines, 'CIS_WARMUP ')
            result = one(lines, 'CIS_RESULT ' if w == 'throughput' else 'CIS_LATENCY ')
            start, end = result['start_ns'], result['end_ns']
            if start != case.get('start_ns') or end <= start or warm.get('operations') != 4096 or warm.get('before_start') != 1 or warm['end_ns'] >= start:
                raise ValueError('window/warmup mismatch')
            if w == 'throughput':
                if result.get('errors') != 0 or result.get('operations', 0) <= 0 or result.get('scheduled_end_ns') != start+2_000_000_000 or end < result['scheduled_end_ns']:
                    raise ValueError('invalid throughput boundary')
                value = result['operations']*1e9/(end-start)
            else:
                parts = one(lines, 'CIS_LATENCY_PARTS ')
                if result.get('count') != 4000 or result.get('rate') != 2000 or result.get('p99_ns', 0) <= 0 or result.get('max_ns', 0) < result['p99_ns'] or not 0 <= result.get('timeouts', -1) <= 4000 or not 40 <= parts.get('tail_count', 0) <= 4000 or parts.get('timerslack_ns', -1) < 0 or end < start+1_999_500_000:
                    raise ValueError('invalid latency census')
                value = result['p99_ns']
                result['parts'] = parts
            data[(boot,)+key] = dict(value=value, result=result, path=path)
        if seen != required:
            raise ValueError('incomplete fixed batch')
        expected = [(w, p, label, role) for w in ('throughput', 'latency') for p in range(5)
                    for label in (('A', 'B') if (boot*5+p) % 2 == 0 else ('B', 'A')) for role in range(2)]
        if sequence != expected:
            raise ValueError('predeclared opposite order differs')
        evidence.append(dict(name=name, sha256=hashlib.sha256(raw).hexdigest(), boot=boot, boot_id=boot_id))
    if sources[0] != sources[1]:
        raise ValueError('mixed source or boot configuration')
    if len({v['result']['parts']['timerslack_ns'] for k,v in data.items() if k[1]=='latency'}) != 1:
        raise ValueError('mixed timer slack')
    rows = []
    for w in ('throughput', 'latency'):
        for role in range(2):
            differences, raw_rows = [], []
            for boot in range(2):
                for p in range(5):
                    a = data[(boot, w, p, 'A', role)]; b = data[(boot, w, p, 'B', role)]
                    difference = 100*((1-b['value']/a['value']) if w == 'throughput' else (b['value']/a['value']-1))
                    differences.append(difference)
                    raw_rows.append(dict(boot=boot, pair=p, a=a, b=b, difference_pct=difference))
            bound = 1 if w == 'throughput' else 2
            ci = interval(differences)
            blocks = [interval(differences[i:i+5]) for i in (0, 5)]
            compatible = all(x['lower95_pct'] >= -bound and x['upper95_pct'] <= bound for x in [ci]+blocks)
            timeout_cells = [dict(boot=row['boot'], pair=row['pair'], label=label,
                                  count=row[label.lower()]['result']['timeouts'])
                             for row in raw_rows for label in ('A', 'B')
                             if w == 'latency' and row[label.lower()]['result']['timeouts']]
            rows.append(dict(workload=w, role=role, tolerance_pct=bound, pooled=ci, boots=blocks,
                             status='PASS' if compatible and not timeout_cells else 'BLOCKED',
                             timeout_cells=timeout_cells, raw=raw_rows))
    return dict(schema='cis-repeatability-report-v1', protocol=PROTOCOL, source=sources[0], evidence=evidence,
                rows=rows, calibration_status='PASS' if all(x['status']=='PASS' for x in rows) else 'BLOCKED',
                observer_admission=False, limits='paired t intervals conditional on sampling assumptions; two boot blocks are reported separately, not ten independent boots')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = analyze([(str(p), p.read_bytes()) for p in args.log])
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2); stream.write('\n')
    print(report['calibration_status'])
