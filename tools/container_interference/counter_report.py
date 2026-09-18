#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual sampled hierarchy updates; never invent a counter lock owner."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from collector_audit import audit
from explain import explain, within_window
from owner_report import fields

OPERATIONS = {1: 'cancel', 2: 'charge', 3: 'try_charge', 4: 'uncharge', 5: 'set_min', 6: 'set_low'}
STAGES = {1: 'begin', 2: 'usage_add', 3: 'usage_sub', 4: 'limit_reverse',
          5: 'rollback', 6: 'children_min_update', 7: 'children_low_update',
          8: 'underflow_correction', 9: 'end'}
MAX_CALLS = 1024


def analyze(record, raw):
    if record.get('collector') != 'counter':
        raise ValueError('counter capture required')
    base = explain(record, raw)
    groups, stacks = defaultdict(list), {}
    generation_addresses = defaultdict(set)
    excluded = Counter()
    known = {(v['id'], v['generation']) for v in record.get('root_identities', {}).values()}
    for line in raw.decode().splitlines():
        item = json.loads(line)
        d = fields(item.get('detail', ''))
        if item.get('kind') == 'stack_symbols' and ' leaf_to_root=' in item.get('detail', ''):
            stacks[d['stack_id']] = item['detail'].split(' leaf_to_root=', 1)[1].split('>')
        if item.get('kind') != 'COUNTER':
            continue
        required = {'protocol', 'sample_time_ns', 'call_ns', 'tid', 'task_start', 'cpu', 'leaf',
                    'object', 'parent', 'operation', 'stage', 'depth', 'ordinal', 'pages', 'usage',
                    'limit_snapshot', 'sample_shift', 'stack_id'}
        if (not required <= d.keys() or d['protocol'] not in (1, 2) or d['operation'] not in OPERATIONS
                or d['stage'] not in STAGES or not 0 <= d['sample_shift'] <= 16
                or min(d['ordinal'], d['depth'], d['pages']) < 0):
            excluded['invalid_schema'] += 1
            continue
        if d['protocol'] == 2 and (not {'leaf_generation','object_generation','parent_generation'} <= d.keys() or
                any(type(d[k]) is not int or not 0 <= d[k] < 2**63 for k in
                    ('leaf_generation','object_generation','parent_generation'))):
            excluded['invalid_schema'] += 1
            continue
        if d['protocol'] == 2:
            if not d['parent'] and d['parent_generation']:
                excluded['invalid_schema'] += 1
                continue
            for address, generation in ((d['leaf'],d['leaf_generation']), (d['object'],d['object_generation']),
                                         (d['parent'],d['parent_generation'])):
                if generation: generation_addresses[generation].add(address)
        who = item.get('id'), item.get('generation'), d['tid'], d['task_start']
        if who[:2] not in known or not all(who) or not d['object'] or not d['leaf']:
            excluded['unknown_identity_or_object'] += 1
            continue
        key = (*who, d['call_ns'])
        if key not in groups and len(groups) >= MAX_CALLS:
            excluded['call_capacity'] += 1
            continue
        groups[key].append(d)
    calls = []
    if any(len(addresses) != 1 for addresses in generation_addresses.values()):
        excluded['invalid_schema'] += 1
    quality_ok = base['quality']['status'] == 'PASS'
    # Malformed records invalidate the stream, not just the convenient row.
    if excluded['invalid_schema']:
        quality_ok = False
        base['quality'] = dict(base['quality'], status='FAIL',
                               defects=base['quality']['defects']+['counter_schema'])
    for key, rows in groups.items():
        rows.sort(key=lambda d: d['ordinal'])
        first, last = rows[0], rows[-1]
        valid = (quality_ok and first['stage'] == 1 and last['stage'] == 9 and
                 last['ordinal'] <= 64 and [r['ordinal'] for r in rows] == list(range(len(rows))) and
                 all(r['stage'] not in (1, 9) for r in rows[1:-1]) and
                 all((r['leaf'], r['operation'], r['sample_shift'], r['stack_id'], r['protocol'], r.get('leaf_generation',0)) ==
                     (first['leaf'], first['operation'], first['sample_shift'], first['stack_id'], first['protocol'], first.get('leaf_generation',0)) for r in rows) and
                 all(a['sample_time_ns'] <= b['sample_time_ns'] for a, b in zip(rows, rows[1:])) and
                 key[-1] <= first['sample_time_ns'] and
                 within_window(record, key[-1], last['sample_time_ns']))
        if not valid:
            excluded['incomplete_or_unaccepted_call'] += 1
            continue
        generations = defaultdict(set)
        for r in rows:
            generations[r['leaf']].add(r.get('leaf_generation', 0))
            generations[r['object']].add(r.get('object_generation', 0))
            if r['parent']: generations[r['parent']].add(r.get('parent_generation', 0))
        if any(len(values) != 1 for values in generations.values()):
            excluded['object_changed_within_call'] += 1
            continue
        if last['usage'] not in (0, 1) or first['operation'] != 3 and last['usage'] != 1:
            excluded['invalid_outcome'] += 1
            continue
        # This verifies the producer's rollback accounting, not contention cost.
        failed = first['operation'] == 3 and last['usage'] == 0
        balance = Counter()
        for r in rows:
            if r['stage'] in (2, 4, 5):
                balance[r['object']] += r['pages'] * (1 if r['stage'] == 2 else -1)
        if failed and (sum(r['stage'] == 4 for r in rows) != 1 or any(balance.values())):
            excluded['incomplete_rollback'] += 1
            continue
        steps = [dict(address=r['object'], parent_address=r['parent'], depth=r['depth'],
                      object_generation=r.get('object_generation',0), parent_generation=r.get('parent_generation',0),
                      stage=STAGES[r['stage']], pages=r['pages'], observed_value=r['usage'],
                      limit_snapshot=r['limit_snapshot'], time_ns=r['sample_time_ns'], cpu=r['cpu'])
                 for r in rows[1:-1]]
        calls.append(dict(evidence='E1', actor=list(key[:4]), call_ns=key[-1], leaf_address=first['leaf'],
                          leaf_generation=first.get('leaf_generation',0),
                          operation=OPERATIONS[first['operation']], interval_ns=[key[-1], last['sample_time_ns']],
                          elapsed_wall_ns=last['sample_time_ns']-key[-1], outcome='limit_failed' if failed else 'completed',
                          failure_address=last['object'] if failed else None, steps=steps,
                          stack_leaf_to_root=stacks.get(first['stack_id'], []), sample_shift=first['sample_shift'],
                          object_lifetime='INIT_GENERATION' if all(next(iter(v)) for v in generations.values()) else 'UNKNOWN',
                          holder=None, spin_cycles=None))
    participants = defaultdict(set)
    for call in calls:
        for step in call['steps']:
            field = 'children_min_usage' if step['stage'] == 'children_min_update' else 'children_low_usage' if step['stage'] == 'children_low_update' else 'usage'
            participants[step['address'], step['object_generation'], field].add(tuple(call['actor']))
    candidates = [dict(address=address, field=field, actors=[list(a) for a in sorted(actors)],
                       relation='shared_address_candidate', evidence='E1', lifetime='UNKNOWN',
                       same_live_object_proven=False, cacheline_contention='UNVERIFIED', holder=None)
                  for (address, generation, field), actors in sorted(participants.items())
                  if not generation and len({a[:2] for a in actors}) > 1]
    shared = [dict(address=address, object_generation=generation, field=field,
                   actors=[list(a) for a in sorted(actors)], relation='shared_counter_updates', evidence='E2',
                   lifetime='INIT_GENERATION', same_live_object_proven=True, cacheline_contention='UNVERIFIED', holder=None)
              for (address, generation, field), actors in sorted(participants.items())
              if generation and len({a[:2] for a in actors}) > 1]
    return dict(schema='cis-counter-report-v1', quality=base['quality'], scope_audit=audit(record, raw),
                object_scope=dict(boot_id=record.get('boot_id'),session_id=record.get('session_id')),
                source=base['source'], raw_sha256=hashlib.sha256(raw).hexdigest(),
                analysis_source_sha256=dict(base['analysis_source_sha256'], **{
                    'counter_report.py': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}),
                calls=calls, address_candidates=candidates[:128], omitted_candidates=max(0, len(candidates)-128),
                shared_objects=shared[:128], omitted_shared_objects=max(0,len(shared)-128),
                excluded=dict(excluded), performance_certification='NOT_ACCEPTED',
                coverage=dict(updates='IMPLEMENTED', rollback='IMPLEMENTED', lifetime='PER_RECORD_INIT_GENERATION_OR_UNKNOWN',
                              cacheline_contention='UNVERIFIED', causal='NOT_CLAIMED'),
                limits=['operation wall time includes observer callbacks, preemption and nested work; not atomic-update cycles',
                        'periodic per-CPU call sampling is not unbiased population sampling; do not multiply into total cost',
                        'pages is the native counter quantity, not always physical memory or bytes',
                        'limit_snapshot can race with updates; failure is established by the native branch event',
                        'children_min/low observed_value is propagation delta, not a usage snapshot',
                        'legacy/zero generation cannot exclude address reuse; init generation identifies an object only within this boot',
                        'E2 shared updates prove participation, not cache-line contention or an inferred holder/blocker'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('record'); p.add_argument('raw'); p.add_argument('output')
    args = p.parse_args()
    if Path(args.raw).stat().st_size > 16 << 20: raise ValueError('input capacity')
    report = analyze(json.loads(Path(args.record).read_text()), Path(args.raw).read_bytes())
    with Path(args.output).open('x') as stream: json.dump(report, stream, indent=2)
    print(json.dumps(dict(quality=report['quality']['status'], calls=len(report['calls']), excluded=report['excluded'])))
