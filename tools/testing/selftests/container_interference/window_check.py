#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify actual bounded collector interval, not request submission time."""
import argparse
import json
import pathlib
import re


def check(text):
    windows, starts, cases, failures = {}, {}, {}, []
    current = observer = None
    for line in text.splitlines():
        if line.startswith('CIS_FILE '):
            m = re.search(r'window-(bench|open-loop)-(off|ip|diag)\.log', line)
            current = (m[1], m[2]) if m else None
            m = re.search(r'observer-(\d+)\.jsonl', line)
            observer = int(m[1]) if m else None
        if current and line.startswith('CIS_FLEET_BEGIN '):
            fields = dict(re.findall(r'(\w+)=([^ ]+)', line))
            cases[current] = fields
            if current[1] == 'diag':
                start = int(fields['start_ns'])
                windows[int(fields['observer_pid'])] = (start, start+int(fields['duration'])*10**9)
        if line.startswith('{'):
            try:
                event = json.loads(line)
            except ValueError:
                failures.append('invalid JSON')
                continue
            if observer in windows and event.get('kind') == 'diagnostic_start':
                fields = dict(re.findall(r'(\w+)=([^ ]+)', event['detail']))
                starts[observer] = fields
            if observer in windows and event.get('kind') == 'E1':
                fields = dict(re.findall(r'(\w+)=([^ ]+)', event['detail']))
                time = int(fields['sample_time_ns'])
                if not windows[observer][0] <= time < windows[observer][1]:
                    failures.append('event outside armed diagnostic interval')
        if current and 'CIS_FLEET_END result=FAIL' in line:
            failures.append(f'{current}: workload failed')
    for pid, (begin, end) in windows.items():
        fields = starts.get(pid, {})
        if (int(fields.get('start_ns', -1)) != begin or
                int(fields.get('deadline_ns', -1)) != end or
                not 0 < int(fields.get('ready_ns', 0)) < begin):
            failures.append(f'{pid}: diagnostic not ready for the full measurement interval')
    expected = {(w, m) for w in ('bench', 'open-loop') for m in ('off', 'ip', 'diag')}
    if set(cases) != expected or len(windows) != 2:
        failures.append('expected six validation cases with two armed intervals')
    return {'pass': not failures, 'failures': failures, 'windows': windows, 'ready': starts,
            'scope': 'attachment and event-window correctness, not performance acceptance',
            'boundary': 'benchmark final batch may straddle end; formal throughput must bound that batch separately'}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('input', type=pathlib.Path)
    p.add_argument('output', type=pathlib.Path)
    a = p.parse_args()
    result = check(a.input.read_text())
    with a.output.open('x') as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['pass'] else 1)
