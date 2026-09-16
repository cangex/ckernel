#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Conservative offline evidence classification, never infer lock holders."""
import argparse
import collections
import json
import pathlib
import re

FIELDS = re.compile(r'(\w+)=([^ ;]+)')


def classify(record):
    fields = dict(FIELDS.findall(record.get('detail', '')))
    result = {k: record[k] for k in ('time_ns', 'id', 'generation', 'name') if k in record}
    result.update(level='E0', relation='unknown', causal=False, fields=fields)
    if record.get('kind') == 'E1':
        kind = int(fields.get('type', '0'))
        result['level'] = 'E1'
        result['observation'] = {2: 'scheduler_wait', 3: 'lock_contention_interval', 4: 'direct_reclaim_interval', 11: 'memcg_reclaim_interval'}.get(kind, 'unsupported')
        result['owner'] = 'unknown'
        result['object_lifetime'] = 'interval_only_unresolved_reuse' if kind == 3 else 'not_applicable'
        result['duration_not_additive'] = True
        result['duration_is_pure_spin'] = False
    elif record.get('kind') == 'incomplete':
        result['observation'] = 'incomplete_pair'
        result['duration_ns'] = None
    else:
        result['observation'] = 'anomaly_without_causal_attribution'
    return result


def analyze(lines):
    evidence, failures, counts = [], [], collections.Counter()
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (ValueError, TypeError):
            failures.append({'line': number, 'reason': 'invalid_json'})
            continue
        counts[record.get('kind', 'invalid')] += 1
        if record.get('kind') in ('E0', 'E1', 'incomplete'):
            evidence.append(classify(record))
    relations = []
    locks = collections.defaultdict(list)
    for item in evidence:
        if item.get('observation') != 'lock_contention_interval':
            continue
        f = item['fields']
        if int(f.get('flags', '0')) & 32:
            locks[f['object']].append(item)
    for obj, items in locks.items():
        active = []
        for item in sorted(items, key=lambda x: int(x['fields']['sample_time_ns'])):
            start = int(item['fields']['sample_time_ns'])
            end = start + int(item['fields']['duration_ns'])
            active = [(limit, prior) for limit, prior in active if limit > start]
            for limit, prior in active:
                if prior['id'] == item['id'] and prior['generation'] == item['generation']:
                    relation = 'same_container_cowaiters'
                else:
                    relation = 'cross_container_cowaiters'
                relations.append({'level':'E2', 'relation':relation, 'object':obj,
                                  'participants':[[prior['id'],prior['generation']],[item['id'],item['generation']]],
                                  'trusted_interval_ns':[start,min(limit,end)],
                                  'owner':'unknown', 'causal':False,
                                  'condition':'supported mutex begin/end protocol and valid kernel object lifetime during both waits'})
            active.append((end,item))
    return {'version': 1, 'evidence': evidence, 'relations':relations, 'record_counts': dict(counts),
            'parse_errors': failures,
            'coverage_boundary': 'E2 co-waiter relation only for overlapping supported mutex intervals; never holder/victim or E3 causality',
            'additive_total': None}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    with args.input.open() as source:
        report = analyze(source)
    with args.output.open('x') as dest:
        json.dump(report, dest, indent=2)
        dest.write('\n')
    return bool(report['parse_errors'])


if __name__ == '__main__':
    raise SystemExit(main())
