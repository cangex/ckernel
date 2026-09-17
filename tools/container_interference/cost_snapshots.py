#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Audit test-harness snapshots without claiming exclusive observer ownership."""
import re

CPU_FIELDS = ('user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal', 'guest', 'guest_nice')


def parse(lines):
    snapshots = {}
    current = None
    errors = []
    for line in lines:
        if line.startswith('CIS_SNAPSHOT '):
            fields = line.split()
            if len(fields) != 3 or fields[1] not in ('start', 'end') or current:
                errors.append('malformed or unfinished snapshot'); current = None; continue
            current = (fields[1], fields[2])
            if current in snapshots:
                errors.append('duplicate snapshot')
            snapshots[current] = []
        elif line == 'CIS_SNAPSHOT_END':
            current = None
        elif current:
            snapshots[current].append(line)
    if current:
        errors.append('truncated snapshot')

    def cpu(phase):
        result = {}
        for line in snapshots.get((phase, '/proc/stat'), []):
            fields = line.split()
            if fields and re.fullmatch(r'cpu(?:\d+)?', fields[0]):
                if len(fields) != 11 or any(not x.isdigit() for x in fields[1:]):
                    errors.append('incomplete CPU counters'); continue
                if fields[0] in result:
                    errors.append('duplicate CPU counters')
                result[fields[0]] = dict(zip(CPU_FIELDS, map(int, fields[1:])))
        return result

    first, last = cpu('start'), cpu('end')
    deltas = {}
    if not first or first.keys() != last.keys():
        errors.append('CPU set changed or counters missing')
    for name in first.keys() & last.keys():
        delta = {key: last[name][key] - first[name][key] for key in CPU_FIELDS}
        if any(v < 0 for k, v in delta.items() if k != 'iowait'):
            errors.append('CPU counter regressed')
        # Linux documents iowait as unreliable, including possible negative deltas.
        deltas[name] = delta

    def scalar(phase, path):
        value = ''.join(snapshots.get((phase, path), []))
        return int(value) if value.isdigit() else None

    memory = [scalar(p, '/sys/fs/cgroup/cis-monitor/memory.current') for p in ('start', 'end')]
    cgcpu = {}
    for phase in ('start', 'end'):
        values = {}
        for line in snapshots.get((phase, '/sys/fs/cgroup/cis-monitor/cpu.stat'), []):
            fields = line.split()
            if len(fields) == 2 and fields[1].isdigit(): values[fields[0]] = int(fields[1])
        cgcpu[phase] = values
    cgdelta = {k: cgcpu['end'][k] - cgcpu['start'][k]
               for k in cgcpu['start'].keys() & cgcpu['end'].keys()}
    if any(x < 0 for x in cgdelta.values()): errors.append('observer cgroup counters regressed')
    return {'cpu_delta_ticks': deltas, 'observer_cgroup_cpu_delta': cgdelta,
            'observer_cgroup_memory_start_end_bytes': memory,
            'quality_errors': errors, 'exclusive_observer_cpu_known': False,
            'memory_total_complete': False,
            'notes': ['System deltas include business and unattributed background; no causal subtraction.',
                      'CPU units are USER_HZ ticks; guest is already included in user/nice.',
                      'iowait is not a reliable additive blocked-time measure.',
                      'memory.current includes shared/charged kernel accounting, not a peak or global total.',
                      'Snapshots are sequential reads, not atomic same-instant CPU and memory observations.']}
