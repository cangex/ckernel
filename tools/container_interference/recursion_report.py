#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Inspect bounded kernel recursion diagnostics; no skipped event is excused."""
import argparse
import json
from pathlib import Path

from session_check import extract


def fields(line):
    return dict(item.split('=', 1) for item in line.split() if '=' in item)


def snapshot(text):
    lines = text.splitlines()
    if not lines:
        raise ValueError('empty snapshot')
    header = fields(lines[0])
    if any(header.get(k) != v for k, v in dict(version='1', enabled='1', trace_active='0', snapshot='non_atomic').items()):
        raise ValueError('diagnosis must be enabled and producers quiescent')
    cpus, phases, samples = {}, [], []
    for line in lines[1:]:
        if not line.strip():
            continue
        value = fields(line)
        if line.startswith('cpu='):
            row = {key: int(value[key]) for key in ('cpu', 'skipped', 'sync', 'irq')}
            if min(row.values()) < 0 or row['cpu'] in cpus or row['skipped'] != row['sync'] + row['irq']:
                raise ValueError('invalid CPU counters')
            cpus[row['cpu']] = row
        elif line.startswith('phase '):
            phases.append({key: int(value[key]) for key in ('cpu', 'kind', 'phase', 'count')})
        elif line.startswith('sample '):
            samples.append({key: int(number, 16 if key in ('object', 'outer', 'caller', 'preempt') else 10)
                            for key, number in value.items()})
        else:
            # CIS_FILE wrappers can append final serial status after a file.
            if line.startswith(('CIS_', '[', 'reboot:', 'Power down')):
                break
            raise ValueError('unrecognized diagnostic line')
    if not cpus:
        raise ValueError('CPU counters missing')
    for row in phases + samples:
        if row['cpu'] not in cpus:
            raise ValueError('orphan sample')
    for cpu, row in cpus.items():
        if sum(p['count'] for p in phases if p['cpu'] == cpu) != row['skipped']:
            raise ValueError('phase totals do not match skipped events')
        subset = [s for s in samples if s['cpu'] == cpu]
        if len(subset) > 8 or any(not 0 < s['count'] <= row['skipped'] for s in subset):
            raise ValueError('invalid bounded sample counters')
    return dict(cpus=cpus, phases=phases, samples=samples,
                skipped=sum(r['skipped'] for r in cpus.values()),
                synchronous=sum(r['sync'] for r in cpus.values()),
                interrupt=sum(r['irq'] for r in cpus.values()),
                bytes_per_possible_cpu=int(header['bytes_per_possible_cpu']))


def analyze(text):
    files = extract(text)
    values = {name: snapshot(body) for name, body in files.items()
              if '/observer-' in name and name.endswith('.log')}
    if not values:
        raise ValueError('no quiescent recursion snapshots')
    peak = max(values.values(), key=lambda x: x['skipped'])
    return dict(schema='cis-recursion-diagnosis-v1', snapshots=values,
                peak_cumulative_skipped=peak['skipped'], synchronous=peak['synchronous'], interrupt=peak['interrupt'],
                caller_addresses=sorted({hex(s['caller']) for value in values.values() for s in value['samples']}),
                limitations=['Counters are cumulative since guest boot, not additive across snapshots.',
                             'Only the last eight examples per CPU are retained, not every skipped event.',
                             'Caller addresses require this guest Image, address randomization and symbol mapping.',
                             'Synchronous recursion does not establish that a skipped object is irrelevant.',
                             'This diagnostic is not a performance acceptance or a fix.'], phase_complete=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('log', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.log.read_text())
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'snapshots'}, indent=2))
