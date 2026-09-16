#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Generate a fail-closed guest S6 runner from a numerically admitted plan."""
import argparse
import hashlib
import json
import pathlib
from acceptance import performance_gate
from scale_plan import matrix


def generate(plan, gate, gate_raw):
    if (plan.get('status') != 'READY_FOR_WINDOW_VALIDATION' or
            plan.get('ambient_result_sha256') != hashlib.sha256(gate_raw).hexdigest() or
            plan.get('cases') != matrix() or not gate.get('pass') or
            not performance_gate('S2', 'ambient_throughput', [gate]) or
            not performance_gate('S2', 'ambient_p99', [gate])):
        raise ValueError('S2 numerical/coverage prerequisite not accepted; no S6 performance launch')
    lines = ['#!/bin/sh', 'set -u', 'failed=0',
             'test "$(grep -c \'^cpu[0-9]\' /proc/stat)" -ge 49 || exit 2',
             'echo CIS_S6_BEGIN']
    for case in plan['cases']:
        stem = 'scale-{family}-{count}-{round}-{workload}-{mode}'.format(**case)
        lines += [f'echo "CIS_PLAN {stem}"',
                  f'/fleet {case["count"]} {case["mode"]} {case["workload"]} {case["seconds"]} {case["target"]} > /tmp/{stem}.log 2>&1 || failed=1']
    for count in plan['idle_counts']:
        for mode in ('off', 'metrics', 'ip'):
            lines.append(f'/fleet {count} {mode} idle 10 0 > /tmp/scale-idle-{count}-{mode}.log 2>&1 || failed=1')
    lines += ['for f in /tmp/scale-*.log /tmp/observer-*.jsonl; do echo "CIS_FILE $f"; cat "$f"; done',
              'echo "CIS_S6_FAILURES=$failed"', 'exit "$failed"']
    return '\n'.join(lines)+'\n'


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('plan', type=pathlib.Path)
    p.add_argument('ambient_result', type=pathlib.Path)
    p.add_argument('output', type=pathlib.Path)
    a = p.parse_args()
    raw = a.ambient_result.read_bytes()
    script = generate(json.loads(a.plan.read_text()), json.loads(raw), raw)
    with a.output.open('x') as f:
        f.write(script)
