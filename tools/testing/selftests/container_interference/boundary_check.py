#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real fixture lifetime reuse and internal-concurrency negative control."""
import argparse
import json
import pathlib
import re
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / 'container_interference'))
from attribution import analyze

FIELDS = re.compile(r'(\w+)=([^ ;]+)')


def check(text):
    current = observer = None
    observer_cases, records = {}, {}
    truth, resets, phases = [], [], []
    failures = []
    for line in text.splitlines():
        if line.startswith('CIS_FILE '):
            current = 'reuse' if 'truth-fixture-reuse.log' in line else 'phase' if 'truth-internal-phase.log' in line else None
            m = re.search(r'observer-(\d+)\.jsonl', line)
            observer = int(m[1]) if m else None
        if current and line.startswith('CIS_FLEET_BEGIN '):
            f = dict(FIELDS.findall(line)); observer_cases[int(f['observer_pid'])] = current
        if current == 'reuse' and line.startswith('CIS_TRUTH '):
            truth.append(dict(FIELDS.findall(line)))
        if current == 'reuse' and line.startswith('CIS_RESET '):
            resets.append(dict(FIELDS.findall(line)))
        if current == 'phase' and line.startswith('CIS_PHASE '):
            phases.append(dict(FIELDS.findall(line)))
        if 'result=FAIL' in line or 'CIS_S4_CONTINUATION_FAILURES=1' in line:
            failures.append(line)
        if line.startswith('{') and observer in observer_cases:
            records.setdefault(observer_cases[observer], []).append(line)
    reuse = analyze(records.get('reuse', []))
    phase = analyze(records.get('phase', []))
    matched = []
    for e in reuse['evidence']:
        if e.get('observation') != 'lock_contention_interval':
            continue
        f = e['fields']; start = int(f['sample_time_ns'])
        candidates = [t for t in truth if t['object']==f['object'] and int(t['cgroup_id'])==e['id'] and
                      int(t['begin_ns'])<=start<=int(t['acquired_ns'])]
        if candidates:
            generations = {int(t['generation']) for t in candidates}
            if len(generations)!=1:
                failures.append('one recorded interval matched multiple fixture object generations')
            matched.append((e, generations))
    cross_generation = 0
    for relation in reuse['relations']:
        start, end = relation['trusted_interval_ns']
        generations = set()
        for e, generation in matched:
            f=e['fields']; begin=int(f['sample_time_ns']); finish=begin+int(f['duration_ns'])
            if f['object']==relation['object'] and begin<=start<finish and end<=finish:
                generations.update(generation)
        cross_generation += len(generations)>1
    generation_count = len({int(t['generation']) for t in truth})
    reuse_ok = len(truth)==400 and len(resets)==2 and generation_count>=2 and len(matched)>100 and not cross_generation
    phase_ok = len(phases)==6 and phase['record_counts'].get('E0', 0)>0 and not phase['relations']
    return {'pass': reuse_ok and phase_ok and not failures, 'failures': failures,
            'reuse': {'pass': reuse_ok, 'truth_operations': len(truth), 'reset_count': len(resets),
                      'observed_generations': generation_count, 'matched_intervals': len(matched),
                      'cross_generation_relations': cross_generation, 'e2_relations': len(reuse['relations']),
                      'scope': 'mutex reinitialization at identical addresses after draining users; not arbitrary allocator lifetime tracing'},
            'internal_phase': {'pass': phase_ok, 'truth_phases': len(phases),
                               'record_counts': phase['record_counts'], 'inferred_cross_container_relations': len(phase['relations']),
                               'scope': 'container-internal 1/4/1 task concurrency, no asserted external cause'}}


if __name__ == '__main__':
    p=argparse.ArgumentParser(); p.add_argument('input',type=pathlib.Path); p.add_argument('output',type=pathlib.Path)
    a=p.parse_args(); result=check(a.input.read_text())
    with a.output.open('x') as f: json.dump(result,f,indent=2)
    print(json.dumps(result,indent=2)); raise SystemExit(0 if result['pass'] else 1)
