#!/usr/bin/env python3
"""Describe cost evidence without assigning global activity to the workload."""
import argparse
import json
from pathlib import Path
import re
import statistics


def cpu_busy_ticks(text, cpus=None):
    rows = dict((p[0], list(map(int, p[1:]))) for line in text.splitlines()
                if (p := line.split()) and re.fullmatch(r'cpu\d*', p[0]))
    keys = ['cpu'] if cpus is None else ['cpu' + str(c) for c in cpus]
    return sum(sum(rows[k][i] for i in (0, 1, 2, 5, 6)) for k in keys)


def device_counts(text, device):
    matches = [line.split()[3:] for line in text.splitlines() if line.split()[2] == device]
    if len(matches) != 1:
        raise ValueError(('device identity missing/duplicated', device))
    f = list(map(int, matches[0]))
    return dict(read_bytes=f[2] * 512, write_bytes=f[6] * 512,
                completed_reads=f[0], completed_writes=f[4], busy_ms=f[9],
                weighted_io_ms=f[10], flushes=f[15] if len(f) >= 17 else None)


def delta(a, b):
    result = {k: b[k] - v if v is not None and b[k] is not None else None for k, v in a.items()}
    if any(v is not None and v < 0 for v in result.values()):
        raise ValueError('counter reset/reuse requires separate adjudication')
    return result


def journal_transactions(before, after):
    if set(before) != set(after):
        raise ValueError('journal identity changed during business')
    def count(text):
        m = re.match(r'^(\d+) transactions ', text)
        if not m:
            raise ValueError('unknown journal summary')
        return int(m[1])
    values = [count(after[k]) - count(before[k]) for k in before]
    if min(values, default=0) < 0:
        raise ValueError('journal counter reset')
    return sum(values)


def analyze(data, clock_ticks):
    if data['phase'] != 'formal' or data['status'] != 'PASS' or data['states'] != 64:
        raise ValueError('complete formal matrix required; no filtering')
    rows = []
    for r in data['results']:
        w = r['window_counters']
        q = r['window_quality']
        a, b = w['before'], w['after']
        p = r['phase_counters']
        quality = 0 <= q['end_offset_ns'] <= 150_000_000 and q['sampler_cpu_ns'] <= 50_000_000
        row = dict(spec=r['spec'], quality_pass=quality, quality=q,
            host_busy_cpu_s=(cpu_busy_ticks(b['host_cpu']) - cpu_busy_ticks(a['host_cpu'])) / clock_ticks,
            management_cpu_s=(cpu_busy_ticks(b['host_cpu'], range(112, 116)) -
                              cpu_busy_ticks(a['host_cpu'], range(112, 116))) / clock_ticks,
            physical_sda_business=delta(device_counts(a['diskstats'], 'sda'), device_counts(b['diskstats'], 'sda')),
            physical_sda_full_experiment=delta(device_counts(p['before_setup']['diskstats'], 'sda'),
                                               device_counts(p['after_teardown']['diskstats'], 'sda')),
            owned_journal_completed_transactions=journal_transactions(a['journals'], b['journals']),
            setup_s=r['setup_ns'] / 1e9, teardown_s=r['teardown_ns'] / 1e9,
            teardown_commands_s={k: v / 1e9 for k, v in r['teardown_command_ns'].items()},
            business_cpu_s=r['business_cpu_s'],
            sum_copy_kernel_peak_bytes=r['summed_copy_peak_memory_bytes'],
            endpoint_current_max_bytes=r['sampled_peak_memory_bytes'], geometry=r['geometry_totals'])
        rows.append(row)
    groups = {}
    for domain in (1, 2, 4, 24):
        loaded = [r for r in rows if r['spec']['domains'] == domain and r['spec']['n'] == 24]
        if len(loaded) != 8:
            raise ValueError('wrong loaded sample count')
        means = {k: statistics.mean(r[k] for r in loaded) for k in (
            'host_busy_cpu_s', 'management_cpu_s', 'business_cpu_s', 'setup_s', 'teardown_s',
            'sum_copy_kernel_peak_bytes', 'endpoint_current_max_bytes', 'owned_journal_completed_transactions')}
        means['teardown_commands_s'] = {k: statistics.mean(r['teardown_commands_s'].get(k, 0) for r in loaded)
            for k in sorted(set().union(*(r['teardown_commands_s'] for r in loaded)))}
        for name in ('physical_sda_business', 'physical_sda_full_experiment'):
            means[name] = {k: statistics.mean(r[name][k] for r in loaded)
                          if all(r[name][k] is not None for r in loaded) else None for k in loaded[0][name]}
        means['quality_failures'] = [r['spec']['name'] for r in loaded if not r['quality_pass']]
        means['usable_bytes_mean'] = statistics.mean(r['geometry']['usable_bytes'] for r in loaded)
        groups[domain] = means
    return dict(groups=groups, states=rows, clock_ticks=clock_ticks,
        quality_failures=[r['spec']['name'] for r in rows if not r['quality_pass']],
        limits=[
            'Host and physical-sda counters include unrelated services; not exclusive workload ownership.',
            'Only physical sda reported: stacked loop/DM/partition counters must not be summed into it.',
            'Journal transaction deltas count commits, not waiting time or all handle coordination.',
            'CPU snapshots have finite width and do not exactly equal replay timing boundaries.',
            'Sum of per-copy kernel peaks is not simultaneous aggregate peak and excludes host-only state.',
            'Full experiment includes preparation, official scoring, teardown and experiment-only fsck.',
            'No complete background-CPU or total-memory noninferiority claim follows from these data.'])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input', type=Path)
    ap.add_argument('--clock-ticks', type=int, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    if args.clock_ticks <= 0:
        raise ValueError('invalid clock ticks')
    result = analyze(json.loads(args.input.read_text()), args.clock_ticks)
    with args.output.open('x') as f:
        json.dump(result, f, indent=2)
    print(json.dumps(dict(groups=result['groups'], quality_failures=result['quality_failures']), indent=2))


if __name__ == '__main__':
    main()
