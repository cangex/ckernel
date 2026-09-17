#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Analyze diagnostic cgroup charges; do not equate them to total observer cost."""
import argparse
import json
from pathlib import Path


def counter_delta(first, last):
    if set(first) != set(last):
        raise ValueError('counter set changed')
    if any(type(v) is not int or v < 0 for v in (*first.values(), *last.values())):
        raise ValueError('invalid counter')
    result = {k: last[k] - first[k] for k in first}
    if any(v < 0 for v in result.values()):
        raise ValueError('counter reset')
    return result


def cpu_bounds(rows, begin, end):
    """Bracket a phase without pretending asynchronous snapshots are simultaneous."""
    if type(begin) is not int or type(end) is not int or begin < 0 or begin > end:
        raise ValueError('CPU phase boundary')
    def boundary(stamp):
        before=[r for r in rows if r.get('end_ns',r['time_ns'])<=stamp]
        after=[r for r in rows if r['time_ns']>=stamp]
        if not before or not after:return None
        return (before[-1]['observer']['cpu_stat']['usage_usec'],
                after[0]['observer']['cpu_stat']['usage_usec'])
    a,b=boundary(begin),boundary(end)
    if a is None or b is None:
        return dict(status='UNKNOWN',reason='stage lacks two-sided counter observations')
    return dict(status='BOUNDED',lower_usec=max(0,b[0]-a[1]),upper_usec=max(0,b[1]-a[0]),
                scope='observer cgroup task CPU only; not asynchronous kernel CPU')


def analyze(value):
    if value.get('schema') != 'cis-resource-timeline-v1':
        raise ValueError('resource timeline schema')
    rows = value['samples']
    if len(rows) < 2 or any(a['time_ns'] >= b['time_ns'] for a, b in zip(rows, rows[1:])):
        raise ValueError('monotonic samples required')
    if any(row.get('errors') for row in rows):
        raise ValueError('incomplete raw snapshots')
    if any(row.get('end_ns',row['time_ns']) < row['time_ns'] for row in rows):
        raise ValueError('snapshot time interval')
    for a,b in zip(rows,rows[1:]):
        counter_delta(a['observer']['cpu_stat'],b['observer']['cpu_stat'])
        counter_delta(a['observer']['memory_events'],b['observer']['memory_events'])
    stages = value['stages']
    if not stages['before_start_ns'] <= stages['daemon_exit_ns'] <= stages['tail_end_ns']:
        raise ValueError('lifecycle stage order')
    if stages['tail_end_ns'] - stages['daemon_exit_ns'] < 5_000_000_000:
        raise ValueError('fixed five-second tail missing')
    charges = [r['observer']['memory_current'] for r in rows]
    peaks = [r['observer']['memory_peak'] for r in rows]
    if any(type(x) is not int or x < 0 for x in charges + peaks):
        raise ValueError('invalid memory charge')
    if any(p < c for p, c in zip(peaks, charges)) or peaks != sorted(peaks):
        raise ValueError('fresh cgroup peak reset/inconsistent')
    observer_cpu = counter_delta(rows[0]['observer']['cpu_stat'], rows[-1]['observer']['cpu_stat'])
    events = counter_delta(rows[0]['observer']['memory_events'], rows[-1]['observer']['memory_events'])
    tail = [r for r in rows if r['time_ns'] >= stages['daemon_exit_ns']]
    if len(tail) < 2 or rows[-1]['time_ns'] < stages['tail_end_ns']:
        raise ValueError('tail observations missing')
    boundaries=[('startup','before_start_ns','daemon_ready_ns'),
                ('workload','workload_start_ns','workload_end_ns'),
                ('finalize','workload_end_ns','daemon_exit_ns'),
                ('post_exit','daemon_exit_ns','tail_end_ns')]
    phases={label:cpu_bounds(rows,stages[a],stages[b]) for label,a,b in boundaries if a in stages and b in stages}
    return dict(schema='cis-resource-timeline-report-v1', diagnostic_only=True,
                mode=value['mode'], timer_control=value['timer_control'],
                samples=len(rows), accounted_memory_peak_bytes=max(peaks),
                sampled_charge_peak_bytes=max(charges),
                charge_before_start_bytes=charges[0], charge_at_tail_end_bytes=charges[-1],
                memory_events_delta=events, observer_cgroup_cpu_delta=observer_cpu,
                observer_tail_cpu_delta=counter_delta(tail[0]['observer']['cpu_stat'], tail[-1]['observer']['cpu_stat']),
                observer_tail_cpu_boundary='first post-exit snapshot; may miss sub-interval CPU',
                cpu_stage_bounds=phases,
                sampler_thread_cpu_ns=value['sampler_thread_cpu_ns'],
                total_memory_complete=False, background_cpu_complete=False,
                missing=['allocations not charged to observer memcg',
                         'shared-page and pre-existing kernel metadata ownership',
                         'BPF in business context and asynchronous worker CPU ownership',
                         'unobserved reclamation later than fixed tail'],
                notes=['memory.peak is a charge high-water mark, not sampled RSS',
                       'cpu.stat includes descendant worker CPU; do not add it again',
                       'global CPU/memory snapshots include workloads and diagnostic sampler',
                       'this tracked batch cannot grant performance acceptance'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('input', type=Path)
    args = p.parse_args()
    print(json.dumps(analyze(json.loads(args.input.read_text())), indent=2))
