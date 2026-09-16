#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Paired observer screen with explicit inconclusive confidence bounds."""
import argparse
import collections
import json
import math
import pathlib
import re
import statistics

VALUES = re.compile(r'(\w+)=([^ ]+)')


def interval(values):
    mean = statistics.mean(values)
    if len(values) < 2:
        return [None, None]
    # Only predeclared cohort sizes; never extend sampling until the CI passes.
    critical = {5: 2.776445105, 20: 2.093024054}
    if len(values) not in critical:
        return [None, None]
    half = critical[len(values)] * statistics.stdev(values) / math.sqrt(len(values))
    return [mean-half, mean+half]


def analyze(text, rounds=5, modes=('metrics', 'ip')):
    records = {}
    current = None
    failures = []
    observer_kinds = collections.Counter()
    observer_errors = []
    observer_case, windows, roots, sampled = {}, {}, collections.defaultdict(set), collections.defaultdict(collections.Counter)
    active_observer = None
    for line in text.splitlines():
        if line.startswith('{'):
            try:
                event = json.loads(line)
            except ValueError:
                failures.append({'reason': 'malformed observer JSON'})
                continue
            observer_kinds[event.get('kind', 'unrelated')] += 1
            case = observer_case.get(active_observer)
            if case and event.get('kind') == 'register':
                roots[case].add(event['id'])
            if case and event.get('kind') == 'IP':
                fields = dict(VALUES.findall(event['detail']))
                begin, finish = windows[case]
                if begin <= int(fields['sample_time_ns']) <= finish:
                    sampled[case][event['id']] += 1
            if event.get('kind') in ('capture_failure','budget_disable','capture_error','sample_schema_error','metrics_budget_disable','budget_unavailable','entry_budget_disable','buffer_loss'):
                observer_errors.append(event)
            if event.get('kind') == 'budget':
                quality = dict(VALUES.findall(event.get('detail', '')))
                if int(quality.get('errors', '0')) or int(quality.get('drops', '0')):
                    observer_errors.append(event)
            if event.get('kind') == 'perf_quality':
                quality = dict(VALUES.findall(event.get('detail', '')))
                if int(quality.get('invalid_records', '0')) or int(quality.get('lost', '0')):
                    observer_errors.append(event)
        if line.startswith('CIS_FILE /tmp/measure-s2-'):
            match = re.search(r'measure-s2-(\d+)-(bench|open-loop)-(off|metrics|ip)\.log', line)
            current = (int(match[1]), match[2], match[3]) if match else None
        if line.startswith('CIS_FILE /tmp/observer-'):
            current = None
            match = re.search(r'observer-(\d+)\.jsonl',line)
            active_observer = int(match[1]) if match else None
        if current and line.startswith('CIS_FLEET_BEGIN '):
            fields = dict(VALUES.findall(line))
            if current[2] == 'ip' and 'observer_pid' in fields:
                observer_case[int(fields['observer_pid'])] = current
                start = int(fields['start_ns'])
                windows[current] = (start,start+int(fields['duration'])*1000000000)
        if 'CIS_FLEET_END result=FAIL' in line:
            failures.append({'case': current, 'reason': line})
        if current and line.startswith(('CIS_RESULT ', 'CIS_LATENCY ')):
            fields = dict(VALUES.findall(line))
            container = int(fields['cgroup'].rsplit('-', 1)[1])
            if current[1] == 'bench':
                value = int(fields['operations']) * 1e9/(int(fields['end_ns'])-int(fields['start_ns']))
            else:
                value = int(fields['p99_ns'])
                if int(fields['timeouts']):
                    failures.append({'case': current, 'reason': 'response timeouts', 'count': int(fields['timeouts'])})
            if (*current, container) in records:
                failures.append({'case': current, 'reason': 'duplicate container result'})
            records[(*current, container)] = value
    results = []
    for workload in ('bench', 'open-loop'):
        for mode in modes:
            for role in ('target', 'bystander'):
                pairs, absolute = [], []
                for run in range(1, rounds+1):
                    container = run % 2 if role == 'target' else 1-run % 2
                    baseline = records.get((run, workload, 'off', container))
                    measured = records.get((run, workload, mode, container))
                    if baseline is None or measured is None or not baseline:
                        continue
                    pairs.append((1-measured/baseline)*100 if workload == 'bench' else (measured/baseline-1)*100)
                    absolute.append(measured-baseline)
                bound = 1 if workload == 'bench' else 2
                ci = interval(pairs) if pairs else [None, None]
                status = 'BLOCKED' if len(pairs) != rounds or ci[1] is None else 'PASS' if ci[1] <= bound else 'FAIL' if ci[0] > bound else 'BLOCKED'
                results.append({'workload': workload, 'mode': mode, 'role': role, 'n': len(pairs),
                                'degradation_percent': pairs, 'mean_percent': statistics.mean(pairs) if pairs else None,
                                '95pct_interval': ci, 'threshold_percent': bound, 'status': status,
                                'mean_absolute_change': statistics.mean(absolute) if absolute else None,
                                'reason': 'confidence_insufficient' if status == 'BLOCKED' else 'predefined_t_interval'})
    missing_coverage=[]
    for run in range(1,rounds+1):
        for workload in ('bench','open-loop'):
            case=(run,workload,'ip')
            if len(roots[case])!=2 or any(not sampled[case][root] for root in roots[case]):
                missing_coverage.append({'case':case,'registered_roots':list(roots[case]),'samples':dict(sampled[case])})
    return {'version': 2, 'environment': 'isolated ARM64 KVM; no bare-metal claim',
            'baseline_mode': 'no daemon/probes; same test harness', 'results': results,
            'failures': failures, 'measurement_count': len(records),
            'observer_kind_counts': dict(observer_kinds), 'observer_errors': observer_errors,
            'missing_coverage': missing_coverage,
            'coverage_valid': not missing_coverage and not observer_errors,
            'predeclared_rounds': rounds, 'compared_modes': modes,
            'pass': len(records) == rounds*2*2*(1+len(modes)) and not failures and not observer_errors and not missing_coverage and all(x['status'] == 'PASS' for x in results),
            'limitations': ['Initial screen: 2 active containers only, not S6 scale coverage.',
                            'Paired t interval assumes independent paired rounds; no significance claim from non-rejection.',
                            'Only read/open/fstat/close workload; not all applications.',
                            'CPU pinning does not reserve host physical resources exclusively.']}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('input', type=pathlib.Path)
    p.add_argument('output', type=pathlib.Path)
    p.add_argument('--rounds', type=int, choices=(5,20), default=5)
    p.add_argument('--full-mode-only', action='store_true')
    args = p.parse_args()
    result = analyze(args.input.read_text(), args.rounds, ('ip',) if args.full_mode_only else ('metrics','ip'))
    with args.output.open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps(result, indent=2))
    return 0 if result['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
