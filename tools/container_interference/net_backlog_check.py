# SPDX-License-Identifier: GPL-2.0
from owner_report import fields


def check_backlog(window, logs, report=None, identities=None):
    if len(logs)!=2: raise ValueError('two container logs required')
    errors=[]; packets=[]; pids=[]; drains=[]
    holds=[fields(s) for s in logs[0].splitlines() if s.startswith('CIS_NET_TRUTH ')]
    for actor,log in enumerate(logs):
        rows=[fields(s) for s in log.splitlines() if s.startswith('CIS_PACKET_TRUTH ')]
        pid=[fields(s)['host_pid'] for s in log.splitlines() if s.startswith('CIS_SESSION_CONTAINER ')]
        drain=[fields(s) for s in log.splitlines() if s.startswith('CIS_PACKET_DRAIN ')]
        if len(pid)!=1 or not pid[0]: errors.append('pid_'+str(actor))
        pids.append(pid[0] if pid else None); packets.append(rows)
        if len(drain)!=1: errors.append('drain_shape_'+str(actor))
        else:
            d=drain[0]; drains.append(d)
            if (d.get('actor')!=actor or d.get('bytes')!=128 or d.get('valid')!=1 or not d.get('cookie') or
                    not window['start_ns']<=d['begin_ns']<d['end_ns']<=window['end_ns']): errors.append('drain_value')
        if [r.get('index') for r in rows]!=list(range(4)): errors.append('packet_shape_'+str(actor))
        for r in rows:
            if (r.get('actor')!=actor or r.get('bytes')!=128 or r.get('valid')!=1 or not r.get('cookie') or
                    not window['start_ns']<=r['begin_ns']<r['end_ns']<=window['end_ns']): errors.append('packet_value')
    if [h.get('index') for h in holds]!=list(range(4)): errors.append('hold_shape')
    if errors: return dict(status='FAIL',errors=errors,eligible=0,captured=0)
    if any(d['begin_ns']<=p[-1]['end_ns'] or d['cookie']!=p[-1]['cookie'] for d,p in zip(drains,packets)):
        errors.append('drain_order')
    matches=[]; cookie=holds[0]['cookie']; address=holds[0]['socket']
    for h,recv,send in zip(holds,packets[0],packets[1]):
        if (not window['start_ns']<=h['enter_ns']<=h['acquired_ns']<send['begin_ns']<send['end_ns']<h['release_begin_ns']<=h['released_ns']<=recv['begin_ns']<=window['end_ns'] or
                h['hold_ms']!=30 or h['actor']!=0 or h['cookie']!=cookie or h['socket']!=address or recv['cookie']!=cookie or send['cookie']==cookie):
            errors.append('hold_send_receive_order_'+str(h['index']))
    if report is not None:
        if report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS' or report['excluded']:
            errors.append('capture_quality')
        sockets=[s for s in report['sockets'] if s['cookie']==cookie and s['socket_address']==address]
        if len(sockets)!=1: errors.append('socket_identity')
        else:
            queues=sockets[0]['backlog']; who=[identities[0]['id'],identities[0]['generation']]
            for h,recv in zip(holds,packets[0]):
                observed=[]
                for q in queues:
                    service=q['service_interval_ns']; executor=q['service_executor']
                    if not h['acquired_ns']<=q['queue_epoch_ns']<=h['release_begin_ns']: continue
                    if (not service or not h['release_begin_ns']<=service[0]<=service[1]<=h['released_ns'] or
                            not executor or executor[:2]!=who or executor[2]&0xffffffff!=pids[0] or
                            not q['release_entry_ns'] or not service[0]<=q['release_entry_ns']<=window['end_ns'] or
                            q['packet_origin']!='UNKNOWN' or q['blocking_container'] is not None):
                        errors.append('queue_closure_'+str(h['index'])); continue
                    observed.append(dict(skb=q['skb_address'],epoch=q['queue_epoch_ns'],service=service,release=q['release_entry_ns'],
                        release_after_receive_return_ns=max(0,q['release_entry_ns']-recv['end_ns'])))
                if not observed: errors.append('missing_queue_slot_'+str(h['index']))
                else: matches.append(dict(index=h['index'],episodes=observed))
    return dict(status='FAIL' if errors else 'PASS',errors=errors,eligible=4,captured=len(matches),
                holds=holds,packets=packets,drains=drains,matches=matches,
                scope='TCP payload verified; per-hold queue/service/release coverage, not one-packet/one-skb recall')
