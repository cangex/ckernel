#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent fixture-call denominator, including calls beyond source caps."""
import hashlib
import json
from collections import defaultdict

from owner_report import fields


POPULATION_PLAN = {
    'schema': 'cis-fd-population-plan-v1',
    'unit': 'complete fixture files_lock/files_unlock call',
    'eligibility': 'all successful fixture calls within the capture window',
    'selection': 'no observed-event, duration, contention or prefix selection',
    'operations_per_thread': 16,
    'relationship_recall': 'UNAVAILABLE; call brackets do not prove spin wait',
}


def check_population(logs, raw, window, case, plan=None):
    if case not in ('threads', 'private', 'native', 'cross', 'reuse'):
        raise ValueError('FD population case')
    if len(logs) != (8 if case == 'reuse' else 2) or len(raw) > 16 << 20:
        raise ValueError('FD population capacity')
    if plan is not None and plan != POPULATION_PLAN:
        raise ValueError('FD population plan changed')
    start, end = window['start_ns'], window['end_ns']
    if not 0 < start < end:
        raise ValueError('FD population window')
    calls, errors, native = [], [], case == 'native'
    for log_index, text in enumerate(logs):
        if len(text.encode()) > 1 << 20:
            raise ValueError('FD truth capacity')
        done, truth = [], []
        for line in text.splitlines():
            if line.startswith('CIS_FD_DONE '):
                done.append(json.loads(line.split(' ', 1)[1]))
            elif line.startswith('CIS_FD_TRUTH '):
                truth.append(json.loads(line.split(' ', 1)[1]))
        count = 1 if case in ('private', 'cross') else 2
        if done != [dict(threads=count, operations_per_thread=16, native=int(native), failed=0)]:
            errors.append('truth_completion')
        if len(truth) != (0 if native else count * 16):
            errors.append('truth_population_size')
        local_calls = []
        for operation, q in enumerate(truth):
            if any(type(q.get(k)) is not int or q[k] <= 0 for k in (
                    'object', 'files', 'tid', 'tgid', 'cgroup_id', 'begin_ns',
                    'acquired_ns', 'release_begin_ns', 'released_ns')):
                errors.append('truth_schema')
                continue
            if q['tid'] >= 1 << 32 or q['tgid'] >= 1 << 32:
                errors.append('truth_task_id_range')
            if not start <= q['begin_ns'] <= q['acquired_ns'] < q['release_begin_ns'] <= q['released_ns'] <= end:
                errors.append('truth_outside_window_or_order')
            calls.append(dict(q, log_index=log_index, operation=operation))
            local_calls.append(q)
        if not native:
            task_counts = defaultdict(int)
            owners = set()
            for q in local_calls:
                task_counts[(q['tgid'], q['tid'])] += 1
                owners.add((q['tgid'], q['cgroup_id'], q['object'], q['files']))
            if len(owners) != 1 or len(task_counts) != count or any(n != 16 for n in task_counts.values()):
                errors.append('truth_task_population')
    # Never trim the denominator to the records the collector happened to see.
    by_task = defaultdict(list)
    for q in calls:
        by_task[(q['tgid'], q['tid'])].append(q)
    for task_calls in by_task.values():
        task_calls.sort(key=lambda q: q['begin_ns'])
        for before, after in zip(task_calls, task_calls[1:]):
            if before['released_ns'] >= after['begin_ns']:
                errors.append('duplicate_or_overlapping_truth_call')
    events, prefixes = defaultdict(list), defaultdict(list)
    sessions = set()
    for index, line in enumerate(raw.splitlines()):
        if index >= 32768:
            raise ValueError('FD event capacity')
        row = json.loads(line)
        if row.get('kind') != 'OWNER':
            continue
        e = fields(row.get('detail', ''))
        if e.get('resource') != 3:
            continue
        sessions.add(row.get('session_id'))
        if not all(type(e.get(k)) is int for k in ('phase', 'object', 'sample_time_ns', 'epoch')):
            errors.append('event_schema')
            continue
        if not start <= e['sample_time_ns'] < end:
            errors.append('event_outside_window')
        if e['phase'] == 11:
            prefixes[e['object']].append(e)
        if e['phase'] in (2, 3, 4):
            events[(e['object'], e.get('actor_id'), e.get('actor_tid'))].append(e)
    if len(sessions) > 1:
        errors.append('mixed_sessions')
    measured, used, full, acquired, absent = [], set(), 0, 0, 0
    for q in calls:
        key = (q['object'], q['cgroup_id'], (q['tgid'] << 32) | q['tid'])
        es = events.get(key, [])
        selected = {}
        for phase, lo, hi in ((2, q['begin_ns'], q['acquired_ns']),
                              (3, q['begin_ns'], q['acquired_ns']),
                              (4, q['release_begin_ns'], q['released_ns'])):
            selected[phase] = [e for e in es if e['phase'] == phase and lo <= e['sample_time_ns'] <= hi]
            if len(selected[phase]) > 1:
                errors.append('duplicate_observation_for_truth_call')
            for e in selected[phase]:
                identity = (key, e['epoch'], phase, e['sample_time_ns'])
                if identity in used:
                    errors.append('observation_matched_twice')
                used.add(identity)
        wait = selected[2][0] if len(selected[2]) == 1 else None
        got = selected[3][0] if len(selected[3]) == 1 else None
        release = selected[4][0] if len(selected[4]) == 1 else None
        observed = [e for e in (wait, got, release) if e]
        identities = {(e.get('actor_generation'), e.get('actor_start'), e['epoch']) for e in observed}
        valid = (len(identities) == 1 and all(all(x) for x in identities)
                 and all(e.get('protocol') == 2 for e in observed))
        pair = bool(valid and wait and got and wait.get('attempt_ns') == wait['sample_time_ns']
                    and got.get('attempt_ns') == wait['attempt_ns']
                    and wait['sample_time_ns'] <= got['sample_time_ns'])
        complete = bool(pair and release and got['sample_time_ns'] < release['sample_time_ns'])
        if observed and not valid:
            errors.append('observation_identity_or_protocol')
        if wait and got and not pair:
            errors.append('observation_pair')
        acquired += pair
        full += complete
        absent += not observed
        # A historical marker is context, not proof of why an event is absent;
        # address reuse and other loss must not be explained away by the cap.
        prior_cap = any(e['sample_time_ns'] <= q['acquired_ns'] for e in prefixes[q['object']])
        measured.append(dict(log_index=q['log_index'], operation=q['operation'],
                             object=hex(q['object']), cgroup_id=q['cgroup_id'],
                             tgid=q['tgid'], tid=q['tid'], begin_ns=q['begin_ns'],
                             observed_phases=[phase for phase in (2, 3, 4) if selected[phase]],
                             acquisition_pair=pair, full_call=complete,
                             prior_address_prefix_marker=prior_cap))
    total = len(calls)
    return dict(schema='cis-fd-population-v1', status='FAIL' if errors else 'PASS_SCOPED',
                errors=sorted(set(errors)),
                design='PREDECLARED' if plan is not None else 'RETROSPECTIVE_REPLAY',
                population=POPULATION_PLAN, calls=measured,
                truth_calls=total, acquisition_pairs=acquired, complete_calls=full,
                partial_calls=total-full-absent, unobserved_calls=absent,
                acquisition_coverage=acquired/total if total else None,
                complete_call_coverage=full/total if total else None,
                prefix_markers=sum(map(len, prefixes.values())),
                denominator_status='UNAVAILABLE_NATIVE' if native else 'INDEPENDENT_FIXTURE_CALLS',
                relationship_recall=None, relationship_recall_status='UNAVAILABLE',
                boundary='call coverage is not contention recall, spin-time accuracy or whole-system coverage; PASS_SCOPED validates accounting, not a recall threshold',
                truth_sha256=[hashlib.sha256(t.encode()).hexdigest() for t in logs])
