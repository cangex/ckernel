#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Validate idle-root coverage and process cost; never substitutes active S6."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import sys
from resource_report import analyze as resources

FIELDS = re.compile(r'(\w+)=([^ ;]+)')


def analyze(text):
    sections, section = {}, 'boot'
    for line in text.splitlines():
        if line.startswith('CIS_FILE '):
            section = line.split(' ', 1)[1]
        else:
            sections.setdefault(section, []).append(line)
    cases, failures = [], []
    for name, lines in sections.items():
        match = re.fullmatch(r'/tmp/control-(128|256)-(metrics|ip|full)\.log', name)
        if not match:
            continue
        count, mode = int(match[1]), match[2]
        begins = [dict(FIELDS.findall(s)) for s in lines if s.startswith('CIS_FLEET_BEGIN ')]
        if len(begins) != 1:
            failures.append(name+': no unique start'); continue
        cfg = begins[0]
        if (cfg.get('cpus') != '64' or cfg.get('duration') != '15' or
                int(cfg.get('count', 0)) != count or 'CIS_FLEET_END result=PASS' not in lines):
            failures.append(name+': failed or wrong configuration')
        start = int(cfg['start_ns']); end = start+15*10**9
        records = [json.loads(s) for s in sections.get('/tmp/observer-'+cfg['observer_pid']+'.jsonl', [])
                   if s.startswith('{"version":')]
        registered, retired = set(), set()
        freshness = collections.defaultdict(list)
        budgets, all_budgets, inventory, quality = [], [], [], []
        full_profile = False
        for r in records:
            k = r['kind']; f = dict(FIELDS.findall(r.get('detail', '')))
            identity = (r['id'], r['generation'])
            if k == 'register': registered.add(identity)
            if k == 'unregister': retired.add(identity)
            if k in ('metric', 'metric_idle'):
                freshness[identity].append(r['time_ns'])
            if k == 'runtime_profile':
                full_profile = f.get('psi_alert') == '1' and f.get('kernel_ip') == '1'
            if k == 'kernel_memory_inventory': inventory.append(f)
            if k == 'perf_quality': quality.append(f)
            if k == 'budget' and f.get('phase') == 'steady':
                all_budgets.append(f)
                if start <= r['time_ns'] < end: budgets.append(f)
                if float(f.get('process_cpu_ns_per_second', 'inf')) > 20_000_000:
                    failures.append(name+': process CPU budget exceeded')
            if k == 'perf_quality' and start <= r['time_ns'] < end and any(
                    int(f.get(x, 0)) for x in ('lost','throttle','invalid_records','unread_cpus')):
                failures.append({'case':name,'event':r})
            if k in ('budget_disable', 'metrics_budget_disable', 'fast_budget_disable',
                     'capture_failure', 'capture_error', 'budget_unavailable',
                     'entry_budget_disable', 'buffer_loss', 'fast_source_error'):
                failures.append({'case': name, 'event': r})
            if k == 'final_quality' and any(int(f.get(x, 0)) for x in ('errors', 'drops')):
                failures.append({'case': name, 'event': r})
        if len(registered) != count or registered != retired:
            failures.append(name+': registration lifecycle mismatch')
        if len(budgets) < 10:
            failures.append(name+': missing steady-state budgets')
        if mode == 'full' and not full_profile:
            failures.append(name+': full profile not active')
        gaps = []
        for identity in registered:
            stamps = sorted(t for t in freshness[identity] if start-10**9 <= t <= end+10**9)
            inside = [t for t in stamps if start <= t < end]
            if len(inside) < 10:
                failures.append(name+': missing one-second empty presence coverage')
            if not inside or inside[0]-start > 1_100_000_000 or end-inside[-1] > 1_100_000_000:
                failures.append(name+': unobserved window boundary')
            gaps.extend(b-a for a, b in zip(stamps, stamps[1:]))
        if gaps and max(gaps) > 1_100_000_000:
            failures.append(name+': one-second presence polling has a gap over 100ms tolerance')
        if mode != 'metrics' and (not quality or not inventory):
            failures.append(name+': missing sampler quality or kernel-memory inventory')
        cases.append({'count': count, 'mode': mode, 'registered': len(registered),
                      'max_process_cpu_ns_per_second': max((float(b['process_cpu_ns_per_second']) for b in budgets), default=None),
                      'max_whole_run_process_cpu_ns_per_second': max((float(b['process_cpu_ns_per_second']) for b in all_budgets), default=None),
                      'max_rss_bytes': max((int(b['rss_bytes']) for b in budgets), default=None),
                      'max_presence_gap_ns': max(gaps, default=None),
                      'memory_inventory': inventory, 'sampler_quality': quality[-1:]})
    if {(x['count'], x['mode']) for x in cases} != {(n,m) for n in (128,256) for m in ('metrics','ip','full')}:
        failures.append('six fixed cases missing')
    if 'CIS_R2_CONTROL_FAILURES=0' not in text:
        failures.append('guest footer failed or missing')
    return {'version': 1, 'raw_sha256': hashlib.sha256(text.encode()).hexdigest(),
            'cases': cases, 'failures': failures, 'process_and_coverage_pass': not failures,
            'resources': resources(text), 'total_memory_accounting_complete': False,
            'scope': '64-vCPU KVM, idle registered roots only; not active S6 or total observer cost'}


if __name__ == '__main__':
    p=argparse.ArgumentParser(); p.add_argument('log',type=Path); p.add_argument('output',type=Path)
    a=p.parse_args(); result=analyze(a.log.read_text())
    with a.output.open('x') as f: json.dump(result,f,indent=2); f.write('\n')
    print(json.dumps({'cases':[{k:v for k,v in c.items() if k not in ('memory_inventory','sampler_quality')} for c in result['cases']],
                      'failures':len(result['failures']),'first_failures':result['failures'][:10],
                      'process_and_coverage_pass':result['process_and_coverage_pass']},indent=2))
    sys.exit(0 if result['process_and_coverage_pass'] else 1)
