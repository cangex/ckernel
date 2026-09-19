# SPDX-License-Identifier: GPL-2.0
"""Closed native Maple wrapper to sampled SLUB call. Not tree lifetime inference."""
from collections import Counter, defaultdict
import json
from explain import within_window
from owner_report import fields


def correlate(record, raw, report):
    supported = 'maple_context' in record.get('inventory', {}).get('program_names', [])
    accepted = report['quality']['status'] == report['scope_audit']['status'] == 'PASS'
    groups = defaultdict(list)
    excluded = Counter()
    required = {'protocol', 'sample_time_ns', 'begin_ns', 'call_ns', 'tid', 'task_start',
                'cpu', 'tree', 'cache', 'operation', 'gfp', 'requested', 'count'}
    for line in raw.decode().splitlines():
        row = json.loads(line)
        if row.get('kind') != 'MAPLE_ALLOC':
            continue
        d = fields(row.get('detail', ''))
        if (not required <= d.keys() or any(type(d[k]) is not int or d[k] < 0 for k in required)
                or d['protocol'] != 1 or d['operation'] not in (1, 2) or not d['tree']
                or not d['cache'] or not d['requested'] or d['count'] not in (0, d['requested'])):
            excluded['schema'] += 1
            continue
        key = (row.get('id'), row.get('generation'), d['tid'], d['task_start'], d['call_ns'])
        if key not in groups and len(groups) >= 1024:
            excluded['capacity'] += 1
            continue
        groups[key].append(d)
    links = []
    for call in report['calls']:
        key = (*call['actor'], call['call_ns'])
        rows = groups.pop(key, [])
        call['maple_context'] = None
        if not rows:
            continue
        if not supported or not accepted or len(rows) != 1:
            excluded['duplicate_or_unaccepted_context'] += len(rows)
            continue
        d = rows[0]
        if (not within_window(record, d['begin_ns'], d['sample_time_ns'])
                or not d['begin_ns'] < call['interval_ns'][0] <= call['interval_ns'][1] <= d['sample_time_ns']
                or d['cache'] != call['cache_address'] or d['count'] != call['returned_count']
                or d['requested'] != call['requested'] or d['gfp'] != call['gfp']
                or d['operation'] != (1 if call['operation'] == 'single' else 2)):
            excluded['backend_mismatch'] += 1
            continue
        value = dict(tree_address=d['tree'], allocation_bracket_ns=[d['begin_ns'], d['sample_time_ns']],
                     backend_call_ns=d['call_ns'], actor=call['actor'], evidence='E2',
                     identity_scope='destination tree valid within this allocation bracket only',
                     tree_owner='UNKNOWN', installed_into_tree='UNOBSERVED', blocking_container=None)
        call['maple_context'] = value
        links.append(value)
    excluded['orphan_context'] += sum(len(v) for v in groups.values())
    excluded = Counter({k: v for k, v in excluded.items() if v})
    # Ambiguous records must not leave apparently good per-call identities behind.
    if excluded or not accepted:
        links = []
        for call in report['calls']:
            call['maple_context'] = None
    return dict(status='FAIL' if excluded else 'PASS' if supported and accepted else 'UNOBSERVED',
                contexts=links, excluded=dict(excluded),
                limits=['tree address is not the SLUB cache or node address',
                        'no cross-bracket tree lifetime, exclusive owner, installed-node or lock-holder claim',
                        'source emits two wrapper callbacks per eligible allocation, not only sampled calls',
                        'release retains allocation context; releasing current is not the tree owner'])
