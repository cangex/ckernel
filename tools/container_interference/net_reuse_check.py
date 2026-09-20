# SPDX-License-Identifier: GPL-2.0
"""Native repeated close/create, independent live ioctl addresses and cookies."""
from owner_report import fields


def check(window,logs,report=None,identities=None):
    errors=[]; truth=[]; matches=0; reused=[]
    cookies=set()
    for actor,log in enumerate(logs):
        pids=[fields(line).get('host_pid') for line in log.splitlines() if line.startswith('CIS_SESSION_CONTAINER ')]
        rows=[fields(line) for line in log.splitlines() if line.startswith('CIS_NET_REUSE ')]
        creates=[fields(line) for line in log.splitlines() if line.startswith('CIS_NET_ORIGIN ')]
        if len(pids)!=1 or not pids[0] or [r.get('index') for r in rows]!=list(range(8)) or len(creates)!=8:
            errors.append('reuse_truth_shape'); continue
        seen={}; previous_end=0; boundaries=[]
        for r,c in zip(rows,creates):
            names=('created_begin_ns','created_end_ns','enter_ns','acquired_ns','release_begin_ns','released_ns','close_begin_ns','close_end_ns')
            times=[r.get(k,-1) for k in names]
            if (r.get('actor')!=actor or not r.get('cookie') or not r.get('socket') or r['cookie'] in cookies or
                    times!=sorted(times) or not window['start_ns']<=times[0]<=times[-1]<=window['end_ns'] or
                    times[0]<previous_end or c.get('operation')!=1 or c.get('cookie')!=r['cookie'] or
                    not times[0]<=c.get('begin_ns',-1)<=c.get('end_ns',-1)<=times[1]):
                errors.append('reuse_truth_value'); continue
            previous_end=times[-1]; cookies.add(r['cookie'])
            if r['socket'] in seen:
                old=seen[r['socket']]
                boundaries.append(dict(socket=r['socket'],before_cookie=old['cookie'],after_cookie=r['cookie'],
                                       closed_ns=old['close_end_ns'],created_ns=r['created_begin_ns']))
            seen[r['socket']]=r
            if report is not None:
                selected=[s for s in report['sockets'] if s['cookie']==r['cookie']]
                if len(selected)!=1: errors.append('reuse_socket_not_observed'); continue
                s=selected[0]; creation=s.get('creation_observation'); ident=identities[actor]
                actors=s.get('observed_actors',[])
                if (s['socket_address']!=r['socket'] or not creation or creation['evidence']!='E2' or
                        not c['begin_ns']<=creation['time_ns']<=c['end_ns'] or not actors or
                        any(a[:2]!=[ident['id'],ident['generation']] or a[2]&0xffffffff!=pids[0] for a in actors) or
                        creation['actor'] not in actors or s.get('accept_observation') or s['waits']):
                    errors.append('wrong_reused_object_identity'); continue
                matches+=1
        if not boundaries: errors.append('native_address_reuse_not_exercised')
        truth.append(rows); reused.append(boundaries)
    if report is not None:
        if report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS' or report['excluded']:
            errors.append('capture_quality')
        if {s['cookie'] for s in report['sockets']}!=cookies: errors.append('unexpected_socket')
    if len(truth)!=2: errors.append('two_actors_required')
    return dict(status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),truth=truth,
                reused_boundaries=reused,matched=matches,eligible=16,
                scope='closed original Socket addresses with fresh native cookies, not kernel-wide lifetime coverage')
