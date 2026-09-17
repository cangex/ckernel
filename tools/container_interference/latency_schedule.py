#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Join bounded guest scheduling traces with post-window request timestamps."""
import argparse
import bisect
import json
from pathlib import Path
import re

from latency_timeline import analyze as request_analyze, fields


def parse_trace(text, pid):
    wake, running = [], []
    precision = 0
    for line in text.splitlines():
        match = re.search(r'\s(\d+)\.(\d+):\s+sched_(waking|switch):\s+(.*)', line)
        if not match:
            continue
        sec, fraction, kind, body = match.groups()
        if len(fraction) > 9:
            raise ValueError('unsupported trace precision')
        precision = max(precision, 10 ** (9 - len(fraction)))
        stamp = int(sec) * 1_000_000_000 + int(fraction.ljust(9, '0'))
        target = re.search(r'\b' + ('pid' if kind == 'waking' else 'next_pid') + r'=(\d+)\b', body)
        if target and int(target[1]) == pid:
            (wake if kind == 'waking' else running).append(stamp)
    return sorted(wake), sorted(running), precision


def analyze(workload, trace, meta, pid):
    summary = request_analyze(workload)
    if type(pid) is not int or pid <= 0 or pid not in meta.get('host_pids', []):
        raise ValueError('registered workload host PID required')
    if meta.get('clock') != 'mono' or not meta.get('diagnostic_only'):
        raise ValueError('guest monotonic diagnostic trace required')
    if not meta.get('cpu_stats') or meta.get('truncated'):
        raise ValueError('trace capacity evidence missing/truncated')
    for stats in meta['cpu_stats'].values():
        # A missing counter is not proof of no event loss.
        if any(type(stats.get(k)) is not int or stats[k] != 0
               for k in ('overrun', 'commit overrun', 'dropped events')):
            raise ValueError('trace loss or missing loss counters')
    wake, running, resolution = parse_trace(trace, pid)
    if not wake or not running:
        raise ValueError('no observed wake/switch events for workload')
    pairs = []
    for item in summary['largest_requests']:
        due, begin = item['due_ns'], item['begin_ns']
        # Account for text formatting precision but never borrow another
        # request's pre-due wake as the explanation for this request.
        lo, hi = bisect.bisect_left(wake, due - resolution), bisect.bisect_right(wake, begin + resolution)
        row = dict(item)
        if hi - lo != 1:
            row.update(status='UNKNOWN', reason='no unique in-request waking event; backlog/prefix possible')
        else:
            w = wake[lo]
            index = bisect.bisect_left(running, w)
            if index >= len(running) or running[index] > begin + resolution:
                row.update(status='UNKNOWN', reason='no matching switch-in before operation')
            else:
                switch = running[index]
                row.update(status='OBSERVED', waking_ns=w, switch_in_ns=switch,
                           due_to_waking_ns=max(0, w-due), waking_to_running_ns=switch-w,
                           running_to_begin_ns=max(0, begin-switch))
        pairs.append(row)
    return dict(schema='cis-latency-schedule-v1', diagnostic_only=True,
                p99_ns=summary['p99_ns'], max_ns=summary['max_ns'],
                tail_wait_mean_ns=summary['tail_wait_mean_ns'],
                tail_execution_mean_ns=summary['tail_execution_mean_ns'],
                text_resolution_ns=resolution, selected_largest_requests=pairs,
                observed=sum(x['status']=='OBSERVED' for x in pairs),
                unknown=sum(x['status']=='UNKNOWN' for x in pairs),
                interpretation='waking-to-running is observed scheduling interval, not lock-holder causality',
                limits=['due-to-waking includes timer slack, timer delivery and possible earlier backlog',
                        'guest trace alone does not identify host vCPU preemption',
                        'largest 32 tail requests are diagnostics, not a full-population attribution rate'])


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('workload', type=Path); p.add_argument('trace', type=Path)
    p.add_argument('meta', type=Path); p.add_argument('pid', type=int)
    a = p.parse_args()
    print(json.dumps(analyze(a.workload.read_text(), a.trace.read_text(), json.loads(a.meta.read_text()), a.pid), indent=2))
