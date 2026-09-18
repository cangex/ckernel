# SPDX-License-Identifier: GPL-2.0
"""Independent ioctl timing brackets and SO_COOKIE, not tracepoint-fed truth."""
from owner_report import fields

CASES=('shared','private','switch')


def case_order():
    return [case+'-'+mode+str(r) for case in CASES for r in range(3)
            for mode in (('off','net') if r%2==0 else ('net','off'))]


def check_case(case,window,logs,report=None,identities=None):
    if case not in CASES or len(logs)!=2: raise ValueError('fixture case')
    errors=[]; truth=[]; pids=[]
    for actor,log in enumerate(logs):
        pid=[fields(line)['host_pid'] for line in log.splitlines() if line.startswith('CIS_SESSION_CONTAINER ')]
        lines=[line for line in log.splitlines() if line.startswith('CIS_NET_TRUTH ')]
        rows=[dict(fields(line), scenario=dict(item.split('=',1) for item in line.split()[1:]).get('scenario'))
              for line in lines]
        if len(pid)!=1 or not pid[0] or [r.get('index') for r in rows]!=list(range(4)):
            errors.append('truth_shape_'+str(actor)); pids.append(None); truth.append([]); continue
        pids.append(pid[0]); truth.append(rows)
        for i,r in enumerate(rows):
            expected_holder=i%2 if case=='switch' else 0
            if (r['actor']!=actor or r['scenario']!=case or not r['cookie'] or not r['socket'] or
                    not window['start_ns']<=r['enter_ns']<=r['acquired_ns']<=r['release_begin_ns']<=r['released_ns']<=window['end_ns'] or
                    r['hold_ms']!=(30 if actor==expected_holder else 0)):
                errors.append('truth_value_'+str(actor)+'_'+str(i))
    eligible=[]; matches=[]
    if len(truth[0])==4 and len(truth[1])==4:
        if len({(r['cookie'],r['socket']) for group in truth for r in group})!=(2 if case=='private' else 1):
            errors.append('socket_identity')
        for i in range(4):
            holder=i%2 if case=='switch' else 0; waiter=1-holder
            h,w=truth[holder][i],truth[waiter][i]
            if h['cookie']==w['cookie'] and h['acquired_ns']<w['enter_ns']<h['release_begin_ns']:
                eligible.append((holder,waiter,i,h,w))
        if len(eligible)!=(0 if case=='private' else 4): errors.append('truth_overlap_incomplete')
    if report is not None:
        if report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS' or report['excluded']:
            errors.append('capture_quality')
        waits=[(sock,wait) for sock in report['sockets'] for wait in sock['waits']]
        for holder,waiter,i,h,w in eligible:
            hid=(identities[holder]['id'],identities[holder]['generation']); wid=(identities[waiter]['id'],identities[waiter]['generation'])
            candidates=[(sock,wait) for sock,wait in waits if sock['cookie']==h['cookie'] and sock['socket_address']==h['socket']
                and tuple(wait['waiter'][:2])==wid and wait['waiter'][2]&0xffffffff==pids[waiter]
                and w['enter_ns']<=wait['interval_ns'][0]<=wait['interval_ns'][1]<=w['acquired_ns']]
            found=[edge for _,wait in candidates for edge in wait['observed_holders'] if edge['holder']
                and tuple(edge['holder'][:2])==hid and edge['holder'][2]&0xffffffff==pids[holder]
                and edge['holder_acquire_ns']<=h['acquired_ns']
                and h['release_begin_ns']<=edge['holder_release_ns']<=h['released_ns']]
            if len(found)!=1: errors.append('missing_or_duplicate_relation_'+str(i))
            else: matches.append(dict(index=i,holder=holder,waiter=waiter,cookie=h['cookie']))
        for sock,wait in waits:
            for edge in wait['observed_holders']:
                if edge['relation_scope']!='cross_container': continue
                if not any(sock['cookie']==h['cookie'] and
                           tuple(wait['waiter'][:2])==(identities[waiter]['id'],identities[waiter]['generation']) and
                           tuple(edge['holder'][:2])==(identities[holder]['id'],identities[holder]['generation']) and
                           w['enter_ns']<=wait['interval_ns'][0]<=wait['interval_ns'][1]<=w['acquired_ns']
                           for holder,waiter,_,h,w in eligible): errors.append('false_cross_container_relation')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,eligible=len(eligible),captured=len(matches),
                recall=len(matches)/len(eligible) if eligible and report is not None else None,
                truth=truth,matches=matches,scope='bounded native TCP logical lock fixture, not production coverage')
