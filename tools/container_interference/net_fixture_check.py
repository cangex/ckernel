# SPDX-License-Identifier: GPL-2.0
"""Independent ioctl timing brackets and SO_COOKIE, not tracepoint-fed truth."""
from owner_report import fields

CASES=('shared','private','switch')
RIGHTS_CASES=('rightsShared','rightsPrivate')
ORIGIN_CASES=RIGHTS_CASES+('rightsAccept',)


def case_order(cases=CASES):
    return [case+'-'+mode+str(r) for case in cases for r in range(3)
            for mode in (('off','net') if r%2==0 else ('net','off'))]


def check_case(case,window,logs,report=None,identities=None,require_origin=False,require_protocol_negative=False):
    if case=='backlog':
        from net_backlog_check import check_backlog
        return check_backlog(window,logs,report,identities)
    if case not in CASES+ORIGIN_CASES or len(logs)!=2: raise ValueError('fixture case')
    private=case in ('private','rightsPrivate'); switching=case=='switch' or case in ORIGIN_CASES
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
            expected_holder=i%2 if switching else 0
            if (r['actor']!=actor or r['scenario']!=case or not r['cookie'] or not r['socket'] or
                    not window['start_ns']<=r['enter_ns']<=r['acquired_ns']<=r['release_begin_ns']<=r['released_ns']<=window['end_ns'] or
                    r['hold_ms']!=(30 if actor==expected_holder else 0)):
                errors.append('truth_value_'+str(actor)+'_'+str(i))
    eligible=[]; matches=[]
    if len(truth[0])==4 and len(truth[1])==4:
        if len({(r['cookie'],r['socket']) for group in truth for r in group})!=(2 if private else 1):
            errors.append('socket_identity')
        for i in range(4):
            holder=i%2 if switching else 0; waiter=1-holder
            h,w=truth[holder][i],truth[waiter][i]
            if h['cookie']==w['cookie'] and h['acquired_ns']<w['enter_ns']<h['release_begin_ns']:
                eligible.append((holder,waiter,i,h,w))
        if len(eligible)!=(0 if private else 4): errors.append('truth_overlap_incomplete')
    if case in ORIGIN_CASES:
        transfers=[[fields(v) for v in log.splitlines() if v.startswith('CIS_NET_RIGHTS ')] for log in logs]
        if any(len(v)!=1 for v in transfers): errors.append('missing_rights_transfer')
        else:
            a,b=transfers[0][0],transfers[1][0]
            if (a.get('actor')!=0 or b.get('actor')!=1 or not a.get('sent_cookie') or
                a['sent_cookie']!=b.get('received_cookie') or a.get('received_cookie')!=0 or b.get('sent_cookie')!=0 or
                a.get('used_cookie')!=a['sent_cookie'] or a.get('private')!=int(private) or b.get('private')!=int(private) or
                (b.get('used_cookie')==a['sent_cookie'])==private): errors.append('wrong_rights_transfer')
            if any(not group or any(r['cookie']!=x.get('used_cookie') for r in group) for group,x in zip(truth,(a,b))):
                errors.append('used_socket_not_transferred_selection')
    origin_matches=[]; origin_expected=0
    excluded_cookies=[]
    if require_protocol_negative:
        for log in logs:
            unsupported=[fields(line) for line in log.splitlines() if line.startswith('CIS_NET_EXCLUDED ')]
            if [(r.get('type'),r.get('protocol')) for r in unsupported]!=[(3,6),(2,17)]:
                errors.append('protocol_negative_truth')
            for row in unsupported:
                if (not row.get('cookie') or row['cookie'] in excluded_cookies or
                    not window['start_ns']<=row.get('begin_ns',-1)<=row.get('end_ns',-1)<=window['end_ns']):
                    errors.append('protocol_negative_identity_or_window')
                excluded_cookies.append(row.get('cookie'))
        if report is not None and any(s['cookie'] in excluded_cookies for s in report['sockets']):
            errors.append('unsupported_socket_captured')
    if require_origin:
        origins=[[fields(line) for line in log.splitlines() if line.startswith('CIS_NET_ORIGIN ')] for log in logs]
        expected=[[1,1,2],[]] if case=='rightsAccept' else [[1],[1] if private else []]
        if [[v.get('operation') for v in group] for group in origins]!=expected:
            errors.append('origin_truth_shape')
        for index,group in enumerate(origins):
            for row in group:
                origin_expected+=1
                if not row.get('cookie') or not window['start_ns']<=row.get('begin_ns',-1)<=row.get('end_ns',-1)<=window['end_ns']:
                    errors.append('origin_truth_window'); continue
                if report is None: continue
                matching=[s for s in report['sockets'] if s['cookie']==row['cookie']]
                field='creation_observation' if row['operation']==1 else 'accept_observation'
                if len(matching)!=1 or not matching[0].get(field):
                    errors.append('origin_not_observed'); continue
                fact=matching[0][field]; ident=identities[index]; who=fact['actor']
                if (fact['evidence']!='E2' or not who or who[:2]!=[ident['id'],ident['generation']]
                    or who[2]&0xffffffff!=pids[index] or not row['begin_ns']<=fact['time_ns']<=row['end_ns']):
                    errors.append('wrong_origin_actor_or_time'); continue
                if row['operation']==2 and matching[0]['creation_owner']!='UNOBSERVED':
                    errors.append('accept_falsely_claimed_creation'); continue
                origin_matches.append(dict(cookie=row['cookie'],operation=row['operation'],actor=index))
        if report is not None:
            expected_facts={(row['cookie'],row['operation']) for group in origins for row in group}
            for sock in report['sockets']:
                for operation,field in ((1,'creation_observation'),(2,'accept_observation')):
                    if sock.get(field) and (sock['cookie'],operation) not in expected_facts:
                        errors.append('unexpected_origin')
    if report is not None:
        if report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS' or report['excluded']:
            errors.append('capture_quality')
        if case in CASES and any(sock.get('creation_observation') or sock.get('accept_observation')
                                 for sock in report['sockets']):
            errors.append('pre_window_origin_fabricated')
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
                origin_expected=origin_expected,origin_captured=len(origin_matches),origin_matches=origin_matches,
                excluded_protocol_cookies=excluded_cookies,
                recall=len(matches)/len(eligible) if eligible and report is not None else None,
                truth=truth,matches=matches,scope='bounded native TCP logical lock fixture, not production coverage')
