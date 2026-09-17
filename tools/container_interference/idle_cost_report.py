#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Analyze the frozen ten-pair idle experiment without creating admission."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import statistics


def paired(values, threshold):
    if len(values) != 10:
        return dict(status='BLOCKED', n=len(values), reason='ten frozen pairs required')
    mean = statistics.mean(values)
    half = 2.262157163 * statistics.stdev(values) / len(values)**.5
    return dict(n=10, mean_pct=mean, lower95_pct=mean-half, upper95_pct=mean+half,
                limit_pct=threshold, pairs_pct=values,
                status='PASS' if mean+half <= threshold else 'FAIL' if mean-half > threshold else 'UNDETERMINED')


def analyze(text):
    files, current = {}, None
    for line in text.splitlines():
        if line.startswith('CIS_FILE '):
            current = Path(line.split(' ', 1)[1]).name
            if current in files: raise ValueError('duplicate artifact name')
            files[current] = []
        elif current:
            files[current].append(line)
    plan = json.JSONDecoder().raw_decode('\n'.join(files['plan.json']).lstrip())[0]
    if plan['pairs'] != 10 or plan['seconds'] != 10 or plan['arrival_rate'] != 2000:
        raise ValueError('not the frozen experiment')
    data, parts, resources = {}, {}, {}
    for workload in ('throughput', 'latency'):
        for repetition in range(10):
            for mode in ('off', 'idle'):
                name = '%s-%02d-%s' % (workload, repetition, mode)
                report = json.JSONDecoder().raw_decode('\n'.join(files[name+'.json']).lstrip())[0]
                if not report['all_children_exit_zero']: raise ValueError('workload exit failure')
                samples = report['samples']
                if not samples: raise ValueError('no resource samples')
                before, end = report['before_controller'], report['after_stop']
                ticks = end['busy_ticks']-before['busy_ticks']
                business = sum(end['cgroup_usage_us'])-sum(before['cgroup_usage_us'])
                resources[name] = dict(
                    vm_busy_cpu_ms=ticks/end['hz']*1000,
                    business_cgroup_cpu_ms=business/1000,
                    nonbusiness_cpu_residual_ms=ticks/end['hz']*1000-business/1000,
                    duration_ns=end['end_ns']-before['begin_ns'],
                    sampled_vm_peak_delta_bytes=max(s['used_vm_bytes'] for s in samples)-before['used_vm_bytes'],
                    post_stop_vm_delta_bytes=end['used_vm_bytes']-before['used_vm_bytes'],
                    largest_snapshot_span_ns=max(s['end_ns']-s['begin_ns'] for s in samples),
                    disclaimer='tick quantization and non-atomic snapshots; residual is not exact observer ownership; sampled memory is not a hard peak')
                for role in range(2):
                    rows = files['%s-%d.log' % (name, role)]
                    prefix = 'CIS_RESULT ' if workload == 'throughput' else 'CIS_LATENCY '
                    entries = [line for line in rows if line.startswith(prefix)]
                    if len(entries) != 1: raise ValueError('missing/duplicate workload result')
                    value = {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', entries[0])}
                    if value['end_ns'] <= value['start_ns']: raise ValueError('nonpositive workload window')
                    if workload == 'throughput':
                        if value['errors']: raise ValueError('business failures')
                        metric = value['operations']*1e9/(value['end_ns']-value['start_ns'])
                    else:
                        if value['count'] != plan['seconds']*plan['arrival_rate']: raise ValueError('arrival count mismatch')
                        metric = value['p99_ns']
                        detail = [line for line in rows if line.startswith('CIS_LATENCY_PARTS ')]
                        if len(detail) != 1: raise ValueError('missing latency components')
                        parts[name+'/'+str(role)] = {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', detail[0])}
                    data[(workload, repetition, mode, role)] = dict(metric=metric, raw=value)
    comparisons = {}
    for workload in ('throughput', 'latency'):
        for role in range(2):
            pairs = [(data[(workload, n, 'off', role)], data[(workload, n, 'idle', role)]) for n in range(10)]
            values = [(1-on['metric']/off['metric'])*100 if workload == 'throughput' else
                      (on['metric']/off['metric']-1)*100 for off, on in pairs]
            summary = paired(values, 1 if workload == 'throughput' else 2)
            summary.update(off_mean=statistics.mean(off['metric'] for off, _ in pairs),
                           idle_mean=statistics.mean(on['metric'] for _, on in pairs),
                           raw_pairs=[dict(off=off, idle=on) for off, on in pairs])
            comparisons[workload+'/'+('target' if role == 0 else 'bystander')] = summary
    return dict(schema=1, phase_complete=False, plan=plan,
                source_log_sha256=hashlib.sha256(text.encode()).hexdigest(),
                complete='CIS_IDLE_COST_COMPLETE=1' in text and 'CIS_PROFILE_VM_EXIT=0' in text,
                comparisons=comparisons, resources=resources, latency_parts=parts,
                receipt_generated=False, resource_budget_pass=False,
                scope='IDLE-only dedicated VM evidence, not periodic-cycle or all-kernel-memory acceptance')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('log', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = analyze(args.log.read_text(errors='replace'))
    with args.output.open('x') as output: json.dump(result, output, indent=2)
    print(json.dumps({key: {k: v for k, v in value.items() if k != 'raw_pairs'}
                      for key, value in result['comparisons'].items()}, indent=2))
