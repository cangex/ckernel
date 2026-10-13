#!/usr/bin/env python3
"""Compact paired results; pilot data never enters formal confidence intervals."""
import argparse
import csv
import json
import math
from pathlib import Path
import statistics as st

def t_cdf_positive(x, df):
    n = 2048
    h = x / n
    factor = math.exp(math.lgamma((df + 1) / 2) - math.lgamma(df / 2)) / math.sqrt(df * math.pi)
    f = lambda y: factor * (1 + y * y / df) ** (-(df + 1) / 2)
    integral = f(0) + f(x)
    integral += 4 * sum(f(h * i) for i in range(1, n, 2))
    integral += 2 * sum(f(h * i) for i in range(2, n, 2))
    return .5 + integral * h / 3

def t_quantile(p, df):
    if not .5 < p < 1 or df < 1:
        raise ValueError('quantile')
    lo, hi = 0., 1.
    while t_cdf_positive(hi, df) < p:
        hi *= 2
    for _ in range(45):
        mid = (lo + hi) / 2
        if t_cdf_positive(mid, df) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2

def paired_ratio(a, b, critical):
    if len(a) != len(b) or len(a) < 2 or min(a + b) <= 0:
        raise ValueError('paired positive data required')
    ratios = [math.log(x / y) for x, y in zip(a, b)]
    mean = st.mean(ratios)
    half = critical * st.stdev(ratios) / math.sqrt(len(ratios))
    return dict(ratio=math.exp(mean), low=math.exp(mean - half), high=math.exp(mean + half))

def peers(row):
    values = [v['elapsed_s'] for v in row['business']['instances'] if v['slot'] != 0]
    return st.mean(values) if values else row['business']['target_s']

def available_mean(values):
    return st.mean(values) if all(v is not None for v in values) else None

def summarize(data):
    rows = data['results'] if isinstance(data, dict) else data
    if any(r['status'] != 'PASS' for r in rows):
        raise ValueError('failed state must be adjudicated, not filtered')
    lookup = {(r['spec']['block'], r['spec']['domains'], r['spec']['n']): r for r in rows}
    if len(lookup) != len(rows):
        raise ValueError('duplicate states')
    groups = {}
    for d in (1, 2, 4, 24):
        solo = [r for r in rows if r['spec']['domains'] == d and r['spec']['n'] == 1]
        loaded = [r for r in rows if r['spec']['domains'] == d and r['spec']['n'] == 24]
        if not solo or not loaded:
            continue
        solo_s = st.mean(r['business']['target_s'] for r in solo)
        loaded_s = st.mean(r['business']['target_s'] for r in loaded)
        groups[d] = dict(domains=d, solo_rounds=len(solo), loaded_rounds=len(loaded),
            solo_s=solo_s, loaded_s=loaded_s, interference_percent=100 * (loaded_s / solo_s - 1),
            peer_mean_s=st.mean(peers(r) for r in loaded),
            batch_s=st.mean(r['batch_s'] for r in loaded),
            business_cpu_s=st.mean(r['business_cpu_s'] for r in loaded),
            stable_kernel_task_cpu_s=available_mean([r['stable_kernel_task_cpu_s'] for r in loaded]),
            sampled_peak_memory_bytes=st.mean(r['sampled_peak_memory_bytes'] for r in loaded),
            setup_s=st.mean(r['setup_ns'] / 1e9 for r in loaded),
            teardown_s=st.mean(r['teardown_ns'] / 1e9 for r in loaded),
            all_active_fraction=st.mean(r['business']['all_active_fraction_of_target'] for r in loaded),
            target_cv_percent=100 * st.stdev(r['business']['target_s'] for r in loaded) / loaded_s if len(loaded) > 1 else None,
            copies=sum(len(r['business']['instances']) for r in solo + loaded))
    return groups, lookup

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    data = json.loads(a.input.read_text())
    groups, lookup = summarize(data)
    result = dict(groups=groups, formal=None,
        limits=['Observation-kernel loop-file experiment, not unmodified OLK or raw-block result.',
                'Host kernel-task counters incompletely attribute background work; sampled memory is not a full peak.',
                'Creation and drain costs are outside replay but reported separately.'])
    if isinstance(data, dict) and data.get('phase') == 'formal':
        if len(lookup) != 64:
            raise ValueError('formal matrix incomplete')
        # Familywise 95% intervals across three candidate-vs-shared comparisons.
        critical = t_quantile(1 - .05 / 6, 7)
        result['formal'] = dict(critical=critical, method='paired log ratios, 8 predefined blocks, three-comparison Bonferroni')
        for d in (2, 4, 24):
            def extract(domain, n, key):
                values = [lookup[b, domain, n] for b in range(8)]
                if key == 'target':
                    return [v['business']['target_s'] for v in values]
                if key == 'peer_mean_s':
                    return [peers(v) for v in values]
                return [v[key] for v in values]
            comparisons = {}
            for n, key in ((24, 'target'), (1, 'target'), (24, 'peer_mean_s'), (24, 'batch_s'),
                           (24, 'business_cpu_s'), (24, 'sampled_peak_memory_bytes')):
                comparisons[f'n{n}_{key}'] = paired_ratio(extract(d, n, key), extract(1, n, key), critical)
            per_slot = {}
            for slot in range(24):
                def times(domain):
                    return [next(v['elapsed_s'] for v in lookup[b, domain, 24]['business']['instances']
                                 if v['slot'] == slot) for b in range(8)]
                per_slot[str(slot)] = paired_ratio(times(d), times(1), critical)
            comparisons['per_slot'] = per_slot
            comparisons['all_slots_noninferior_2pct'] = all(v['high'] <= 1.02 for v in per_slot.values())
            comparisons['solo_and_batch_noninferior_2pct'] = all(
                comparisons[k]['high'] <= 1.02 for k in ('n1_target', 'n24_peer_mean_s', 'n24_batch_s'))
            if all('summed_copy_peak_memory_bytes' in lookup[b, d, 24] for b in range(8)):
                comparisons['summed_copy_peak_memory'] = paired_ratio(
                    extract(d, 24, 'summed_copy_peak_memory_bytes'),
                    extract(1, 24, 'summed_copy_peak_memory_bytes'), critical)
            # No net-benefit PASS is inferred from incomplete background/memory attribution.
            target = comparisons['n24_target']
            comparisons['business_target_supported'] = target['ratio'] <= .97 and target['high'] < 1
            comparisons['net_benefit'] = 'NOT_ESTABLISHED: background ownership, total memory and mechanism checks remain separate'
            result['formal'][str(d)] = comparisons
    a.output.mkdir(exist_ok=False)
    (a.output / 'summary.json').write_text(json.dumps(result, indent=2))
    with (a.output / 'summary.csv').open('w') as f:
        w = csv.DictWriter(f, fieldnames=list(next(iter(groups.values()))))
        w.writeheader()
        w.writerows(groups.values())
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
