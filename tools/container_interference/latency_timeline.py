#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Decompose diagnostic request timing without attributing a cause to lateness."""
import argparse
import json
from pathlib import Path
import re


def fields(line):
    return {key: int(value) for key, value in re.findall(r'(\w+)=(\d+)', line)}


def analyze(text):
    headers = [fields(line) for line in text.splitlines() if line.startswith('CIS_LATENCY_TIMELINE ')]
    results = [fields(line) for line in text.splitlines() if line.startswith('CIS_LATENCY ')]
    if len(headers) != 1 or len(results) != 1:
        raise ValueError('one diagnostic timeline and one workload result required')
    result, header = results[0], headers[0]
    count = header['count']
    if not 1 <= count <= 20000 or count != result['count'] or header.get('post_window_export') != 1:
        raise ValueError('timeline count or export boundary')
    samples = [fields(line) for line in text.splitlines() if line.startswith('CIS_LATENCY_SAMPLE ')]
    if len(samples) != count or [x['index'] for x in samples] != list(range(count)):
        raise ValueError('missing, duplicate or reordered request')
    for item in samples:
        expected = result['start_ns'] + item['index'] * 1000000000 // result['rate']
        if item['due_ns'] != expected or not item['due_ns'] <= item['begin_ns'] <= item['finish_ns'] <= result['end_ns']:
            raise ValueError('invalid request timing')
        item['arrival_wait_ns'] = item['begin_ns'] - item['due_ns']
        item['execution_ns'] = item['finish_ns'] - item['begin_ns']
        item['response_ns'] = item['finish_ns'] - item['due_ns']
    observed = sorted(x['response_ns'] for x in samples)
    p99 = observed[(count * 99 + 99) // 100 - 1]
    if p99 != result['p99_ns'] or observed[-1] != result['max_ns']:
        raise ValueError('summary does not match per-request timestamps')
    tail = [item for item in samples if item['response_ns'] >= p99]
    return dict(schema='cis-latency-timeline-v1', diagnostic_only=True, phase_complete=False,
                clock='guest_monotonic', host_clock_alignment=None, count=count,
                p99_ns=p99, max_ns=observed[-1], tail_count=len(tail),
                tail_wait_mean_ns=sum(x['arrival_wait_ns'] for x in tail) / len(tail),
                tail_execution_mean_ns=sum(x['execution_ns'] for x in tail) / len(tail),
                largest_requests=sorted(tail, key=lambda x: x['response_ns'], reverse=True)[:32],
                cause='unattributed: arrival wait includes wakeup delay and earlier-request backlog; execution includes blocking',
                measurement='existing timestamps exported after window; no inferred host-vCPU cause')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('log', type=Path)
    parser.add_argument('--artifact', help='exact CIS_FILE path in a VM serial log')
    args = parser.parse_args()
    text = args.log.read_text()
    if args.artifact:
        from session_check import extract
        text = extract(text)[args.artifact]
    print(json.dumps(analyze(text), indent=2))
