# SPDX-License-Identifier: GPL-2.0
"""Independent bounded blk-mq API truth. Not ordinary-application coverage."""

CASES = ('exhausted', 'private', 'available', 'nowait')


def order():
    return ['%s-%s-%d' % (case, mode, r) for case in CASES for r in range(3)
            for mode in (('off', 'block') if r % 2 == 0 else ('block', 'off'))]


def check(evidence, report=None, identities=None):
    errors = []
    case = evidence['case']
    if case not in CASES:
        raise ValueError('tag fixture case')
    rows = evidence['truth']
    calls = [r for r in rows if r['actor']==1 and r['op']==0]
    holder = [r for r in rows if r['actor']==0 and r['op']==0]
    if len(calls)!=1 or len(holder)!=(3 if case=='available' else 4):
        return dict(status='FAIL', errors=['call_population'])
    call = calls[0]
    if (call['result']!=(-11 if case=='nowait' else 0) or any(r['result'] for r in holder)
            or any(r['depth']!=4 for r in rows)):
        errors.append('native_allocation_result')
    if call['disk'] != (1 if case=='private' else 0) or call['nowait']!=int(case=='nowait'):
        errors.append('case_route')
    if evidence['held_before'] != [len(holder),0]:
        errors.append('independent_held_count')
    w=evidence['window']
    if any(not w['start_ns']<=r['before_ns']<=r['after_ns']<=w['end_ns'] for r in rows):
        errors.append('truth_outside_window')
    matched=0
    if report is not None:
        if report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS':
            errors.append('capture_quality')
        tags=report['tag_waits']
        expected=1 if case in ('exhausted','nowait') else 0
        if len(tags)!=expected:
            errors.append('tag_population')
        for tag in tags:
            if (tag['tid']!=call['tid'] or tag['task_start']!=call['task_start'] or tag['queue']!=call['queue']
                    or tag['container']!=[identities[1]['id'],identities[1]['generation']]
                    or tag['identity_changes'] or tag['blocking_container'] is not None
                    or tag['request_allocation_success']!='NOT_ESTABLISHED'):
                errors.append('tag_identity')
            a,b=tag['interval_ns']
            if b is None or not call['before_ns']<=a<=b<=call['after_ns']:
                errors.append('tag_boundary')
            if case=='exhausted':
                frees=[r for r in rows if r['actor']==0 and r['op']==1]
                if (tag['outcome']!='TAG_FOUND' or not tag['sleep_intervals'] or len(frees)!=1
                        or not a<frees[0]['before_ns']<=b
                        or sum(y-x for x,y in (s['interval_ns'] for s in tag['sleep_intervals']))<20_000_000):
                    errors.append('real_sleep_not_confirmed')
            elif tag['outcome']!='NOWAIT_REJECTED' or tag['sleep_intervals']:
                errors.append('nowait_not_sleep')
            matched+=1
        if report['requests']:
            errors.append('fixture_did_not_submit_io')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,tag_matches=matched,
                expected_tags=1 if case in ('exhausted','nowait') else 0,
                scope='native blk-mq allocation API fixture; not device I/O or unique holder inference')
