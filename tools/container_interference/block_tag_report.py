# SPDX-License-Identifier: GPL-2.0
"""Tag-allocation episodes, not a claim about which request owns every slot."""
from collections import Counter, defaultdict
import json

from explain import within_window
from owner_report import fields

REQUIRED = {'protocol', 'sample_time_ns', 'episode_ns', 'tid', 'task_start',
            'queue', 'pool', 'phase', 'alloc_flags', 'tag', 'dev_major', 'dev_minor',
            'actor_id', 'actor_generation', 'cpu', 'stack_id'}


def tag_episodes(record, raw):
    groups = defaultdict(list)
    defects = Counter()
    identities = dict(record.get('root_identities', {}))
    identities.update(record.get('owner_identities', {}))
    known = {(x['id'], x['generation']) for x in identities.values()}
    count = 0
    for line in raw.decode().splitlines():
        item = json.loads(line)
        if item.get('kind') != 'BLOCK_TAG':
            continue
        count += 1
        if count > 16384:
            defects['tag_record_capacity'] += 1
            continue
        d = fields(item.get('detail', ''))
        if (not REQUIRED <= d.keys() or any(type(d[k]) is not int for k in REQUIRED)
                or any(d[k] < 0 for k in REQUIRED - {'tag', 'stack_id'})
                or d['protocol'] != 1 or not 1 <= d['phase'] <= 5
                or d['stack_id'] < -4095 or d['tag'] < -1
                or not all(d[k] for k in ('episode_ns', 'queue', 'pool', 'tid', 'task_start'))):
            defects['tag_schema'] += 1
            continue
        who = (item.get('id'), item.get('generation'))
        actor = (d['actor_id'], d['actor_generation'])
        if (who not in known or actor != (0, 0) and actor not in known
                or d['phase'] in (1,5) and actor != who):
            defects['tag_identity'] += 1
            continue
        if not within_window(record, d['episode_ns'], d['sample_time_ns']):
            defects['tag_outside_window'] += 1
            continue
        d['owner'] = who
        key = (d['tid'], d['task_start'], d['episode_ns'])
        if key not in groups and len(groups) >= 4096:
            defects['tag_episode_capacity'] += 1
            continue
        groups[key].append(d)
    results = []
    lifetimes = defaultdict(list)
    for key, rows in sorted(groups.items()):
        rows.sort(key=lambda r: r['sample_time_ns'])
        first = rows[0]
        if first['phase'] not in (1, 5) or first['sample_time_ns'] != key[2]:
            defects['tag_missing_start'] += 1
            continue
        if bool(first['alloc_flags'] & 1) != (first['phase']==5):
            defects['tag_nowait_flags'] += 1
            continue
        terminal = None
        pending = None
        sleeps = []
        changes = []
        pools = []
        bad = Counter()
        for i, row in enumerate(rows):
            phase, now = row['phase'], row['sample_time_ns']
            if terminal is not None:
                bad['tag_after_terminal'] += 1
                continue
            if (row['owner'] != first['owner'] or row['queue'] != first['queue']
                    or row['alloc_flags'] != first['alloc_flags']
                    or (row['dev_major'], row['dev_minor']) != (first['dev_major'], first['dev_minor'])):
                bad['tag_call_identity_changed'] += 1
            if (row['actor_id'], row['actor_generation']) != first['owner']:
                changes.append(dict(time_ns=now, actor=[row['actor_id'], row['actor_generation']]))
            pools.append(row['pool'])
            if phase in (1, 5):
                if i or row['tag'] != -1:
                    bad['tag_invalid_start'] += 1
                if phase == 5:
                    terminal = now
            elif phase == 2:
                if pending is not None or row['tag'] != -1:
                    bad['tag_nested_sleep'] += 1
                pending = row
            elif phase == 3:
                if pending is None or pending['pool'] != row['pool'] or row['tag'] != -1:
                    bad['tag_unmatched_wakeup'] += 1
                else:
                    sleeps.append(dict(interval_ns=[pending['sample_time_ns'], now], pool=row['pool'],
                                       begin_cpu=pending['cpu'], end_cpu=row['cpu']))
                pending = None
            elif phase == 4:
                if pending is not None or row['tag'] < 0:
                    bad['tag_invalid_found'] += 1
                terminal = now
        defects.update(bad)
        if bad:
            continue
        lifetimes[key[:2]].append([key[2], terminal])
        results.append(dict(tid=key[0], task_start=key[1], episode_ns=key[2],
            container=list(first['owner']), queue=first['queue'], device=[first['dev_major'], first['dev_minor']],
            interval_ns=[key[2], terminal], sleep_intervals=sleeps,
            outcome='NOWAIT_REJECTED' if first['phase']==5 else 'TAG_FOUND' if terminal is not None else 'UNOBSERVED',
            pools=list(dict.fromkeys(pools)), pool_changed=len(set(pools))>1,
            identity_changes=changes, unfinished_sleep=pending is not None,
            stack_id=first['stack_id'], evidence='E1', blocking_container=None,
            request_allocation_success='NOT_ESTABLISHED', causal='NOT_ESTABLISHED'))
    for intervals in lifetimes.values():
        intervals.sort()
        if any(a[1] is None or a[1]>=b[0] for a,b in zip(intervals,intervals[1:])):
            defects['tag_overlapping_task_episodes'] += 1
    return results, dict(defects)
