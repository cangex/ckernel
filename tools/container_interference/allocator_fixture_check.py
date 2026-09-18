# SPDX-License-Identifier: GPL-2.0
"""Independent ioctl truth versus selected-cache native allocation records."""
from owner_report import fields

CASES = ('cold', 'warm', 'bulk', 'private', 'migration')


def case_order():
    return ['%s-%s%d' % (case,mode,round_number) for case in CASES for round_number in range(3)
            for mode in (('off','allocator') if round_number % 2 == 0 else ('allocator','off'))]


def check_case(case, window, logs, report=None, identities=None):
    if case not in CASES or len(logs) != 2:
        raise ValueError('frozen case and two container actors required')
    errors, participants, total, captured = [], [], 0, 0
    selected_addresses, private_addresses = set(), set()
    for index, log in enumerate(logs):
        pids = [fields(line).get('host_pid') for line in log.splitlines()
                if line.startswith('CIS_SESSION_CONTAINER ')]
        rows = [fields(line) for line in log.splitlines() if line.startswith('CIS_ALLOC_TRUTH ')]
        alloc = [r for r in rows if r.get('action') == 1]
        frees = [r for r in rows if r.get('action') == 2]
        shrinks = [r for r in rows if r.get('action') == 3]
        bulk, count = int(case in ('bulk', 'migration')), 1 if case == 'cold' else 4
        if bulk: count = 8
        cache = int(case == 'private' and index == 1)
        expected_actions = [3, 1, 2] * 4 if case == 'cold' else [1, 2] * 4
        valid = (len(pids) == 1 and pids[0] and [r.get('action') for r in rows] == expected_actions
                 and [r.get('index') for r in alloc] == list(range(4))
                 and [r.get('index') for r in frees] == list(range(4)))
        for r in rows:
            valid = valid and (r.get('cache') == cache and r.get('cache_address', 0) > 0
                and window['start_ns'] <= r.get('begin_ns', -1) < r.get('end_ns', -1) <= window['end_ns']
                and r.get('result') in ((0, 1) if r.get('action') == 3 else (0,)))
        for r in alloc:
            valid = valid and r.get('count') == count and r.get('returned') == count and r.get('bulk') == bulk and r.get('cpu') == index
        for r in frees:
            valid = valid and r.get('count') == 0 and r.get('returned') == count and r.get('bulk') == bulk and r.get('cpu') == index + (2 if case == 'migration' else 0)
        for r in shrinks:
            valid = valid and r.get('count') == 0 and r.get('returned') == 0
        addresses = {r.get('cache_address') for r in rows}
        if len(addresses) != 1: valid = False
        (private_addresses if cache else selected_addresses).update(addresses)
        if not valid:
            errors.append('truth_' + str(index))
            continue
        eligible = 0 if cache else len(alloc) * (1 if bulk else count)
        found = []
        if report is not None:
            identity = identities[index]
            calls = [c for c in report['calls'] if c['actor'][:2] == [identity['id'], identity['generation']]
                     and c['actor'][2] & 0xffffffff == pids[0]]
            for r in alloc:
                group = [c for c in calls if r['begin_ns'] <= c['interval_ns'][0] < c['interval_ns'][1] <= r['end_ns']]
                expected = 0 if cache else 1 if bulk else count
                if len(group) != expected: errors.append('capture_count_%d_%d' % (index, r['index']))
                for c in group:
                    if (c['cache_address'] != r['cache_address'] or c['sample_shift'] != 0
                            or c['operation'] != ('bulk' if bulk else 'single')
                            or c['requested'] != (count if bulk else 1)
                            or c['returned_count'] != c['requested'] or c['rolled_back_count']):
                        errors.append('call_truth_%d_%d' % (index, r['index']))
                found.extend(group)
            if len(calls) != len(found): errors.append('unexpected_actor_call_' + str(index))
        total += eligible
        captured += len(found)
        participants.append(dict(actor=index,truth_allocation_calls=eligible,captured_calls=len(found),
            operations=alloc,release_operations=frees,free_attribution='NOT_OBSERVED'))
    if selected_addresses & private_addresses or len(selected_addresses) != 1:
        errors.append('cache_identity')
    if report is not None and (report['quality']['status'] != 'PASS' or report['scope_audit']['status'] != 'PASS'
                               or report['excluded']):
        errors.append('capture_quality')
    return dict(status='FAIL' if errors else 'PASS', errors=errors, participants=participants,
        eligible=total, captured=captured, selected_call_recall=captured / total if report is not None and total else None,
        scope='selected-cache allocation calls only; release truth does not prove free attribution',
        performance_certification='NOT_ACCEPTED')
