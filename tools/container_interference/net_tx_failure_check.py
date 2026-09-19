# SPDX-License-Identifier: GPL-2.0
"""Independent syscall truth for native TCP header allocation failure/recovery."""
from owner_report import fields

CASES = ('txfailure', 'txunmarked')


def check(case, window, logs, report=None, identities=None):
    if case not in CASES or len(logs) != 2:
        raise ValueError('frozen TCP allocation failure cases')
    errors = []; participants = []; all_cookies = set()
    for actor, log in enumerate(logs):
        pids = [fields(v).get('host_pid') for v in log.splitlines() if v.startswith('CIS_SESSION_CONTAINER ')]
        truth = [fields(v) for v in log.splitlines() if v.startswith('CIS_NET_TX_FAILURE ')]
        if len(pids) != 1 or not pids[0] or [v.get('index') for v in truth] != list(range(8)):
            errors.append('truth_count_' + str(actor)); continue
        episodes = []
        if report is not None:
            identity = identities[actor]
            episodes = [e for e in report['tx']['episodes'] if e['requester'][:2] == [identity['id'], identity['generation']]
                        and e['requester'][2] & 0xffffffff == pids[0]]
            if len(episodes) != 8: errors.append('episode_count_' + str(actor))
        found = []; cookies = set(); failed = 0
        for r in truth:
            i = r['index']; armed = int(i % 2 == 0 and (actor == 0 or case == 'txfailure'))
            cookies.add(r.get('cookie')); failed += armed
            if (r.get('armed') != armed or r.get('returned') != (-1 if armed else 128)
                    or r.get('error') != (11 if armed else 0) or r.get('received') != (0 if armed else 128)
                    or r.get('restored') != 1 or not r.get('cookie')
                    or not window['start_ns'] <= r.get('begin_ns', -1) < r.get('end_ns', -1) <= window['end_ns']):
                errors.append('truth_%d_%d' % (actor, i)); continue
            if report is None: continue
            match = [e for e in episodes if e['cookie'] == r['cookie'] and
                     r['begin_ns'] <= e['begin_ns'] <= e['backend_interval_ns'][0] <= e['backend_interval_ns'][1]
                     <= (e['terminal_ns'] or 0) <= r['end_ns']]
            if len(match) != 1:
                errors.append('send_match_%d_%d' % (actor, i)); continue
            e = match[0]; found.append(e)
            if (e['outcome'] != ('BACKEND_ALLOCATION_FAILED' if armed else 'ADMITTED')
                    or e['packet_payload_owner'] != 'UNKNOWN' or e['blocking_container'] is not None
                    or e['allocator_lock_holder'] is not None or e['backend_cpu_ns'] is not None):
                errors.append('outcome_%d_%d' % (actor, i))
            if armed:
                if e['skb_address'] or e['release_entry_ns'] is not None:
                    errors.append('fabricated_allocation_%d_%d' % (actor, i))
            elif not e['skb_address'] or not e['terminal_ns'] <= (e['release_entry_ns'] or 0) <= window['end_ns']:
                errors.append('unclosed_recovery_%d_%d' % (actor, i))
        if len(cookies) != 1 or cookies & all_cookies: errors.append('private_socket_' + str(actor))
        all_cookies |= cookies
        participants.append(dict(actor=actor,eligible=len(truth),captured=len(found),failed_sends=failed,
                                 successful_sends=8-failed))
    if report is not None and (report['quality']['status'] != 'PASS' or report['scope_audit']['status'] != 'PASS'
                              or report['tx']['status'] != 'PASS' or report['tx']['excluded'] or report['tx']['unknown']
                              or any(s['waits'] for s in report['sockets']) or len(report['tx']['episodes']) != 16):
        errors.append('quality_or_private_relationship')
    return dict(status='FAIL' if errors else 'PASS', errors=errors, participants=participants,
                scope='native failslab TCP original header allocation, task isolation and unmarked recovery',
                memory_admission_failure='UNVERIFIED', performance_certification='NOT_ACCEPTED')
