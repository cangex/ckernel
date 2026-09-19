# SPDX-License-Identifier: GPL-2.0
"""Queue acceptance truth, not wire delivery or an allocator-holder claim."""
from owner_report import fields

CASES=('txadmission','txnormal')


def check(case,window,logs,configuration,restored,report=None,identities=None):
    if case not in CASES or len(logs)!=2: raise ValueError('frozen admission cases')
    errors=[]; participants=[]; cookies=set()
    if configuration['limited']!=(case=='txadmission') or restored['limited'] or not (
            configuration['time_ns']<window['start_ns']<restored['time_ns']<window['end_ns']):
        errors.append('configuration_order')
    if case=='txadmission' and configuration['tcp_mem'].split()!=['0']*3: errors.append('pressure_not_enabled')
    if len(restored['tcp_mem'].split())!=3 or any(int(v)<=0 for v in restored['tcp_mem'].split()):
        errors.append('invalid_restored_budget')
    if case=='txnormal' and configuration['tcp_mem'].split()!=restored['tcp_mem'].split():
        errors.append('normal_budget_changed')
    for actor,log in enumerate(logs):
        pids=[fields(v).get('host_pid') for v in log.splitlines() if v.startswith('CIS_SESSION_CONTAINER ')]
        truth=[fields(v) for v in log.splitlines() if v.startswith('CIS_NET_TX_ADMISSION ')]
        resumed=[fields(v) for v in log.splitlines() if v.startswith('CIS_NET_TX_RESTORED ')]
        if (len(pids)!=1 or len(resumed)!=1 or not pids[0] or
                [(v.get('phase'),v.get('index')) for v in truth]!=[(p,i) for p,n in ((0,16),(1,8)) for i in range(n)]):
            errors.append('truth_population_'+str(actor)); continue
        if not restored['time_ns']<resumed[0]['time_ns']<window['end_ns']: errors.append('resume_order')
        own={v.get('cookie') for v in truth}
        if len(own)!=1 or not all(own) or own&cookies: errors.append('private_socket')
        cookies|=own
        episodes=[]
        if report is not None:
            identity=identities[actor]
            episodes=[e for e in report['tx']['episodes'] if e['requester'][:2]==[identity['id'],identity['generation']]
                      and e['requester'][2]&0xffffffff==pids[0]]
            if len(episodes)!=24: errors.append('allocation_count_'+str(actor))
        found=[]; failures=0; rejected=0
        for r in truth:
            if (r.get('actor')!=actor or not window['start_ns']<=r['begin_ns']<r['end_ns']<=window['end_ns']
                    or (r['returned'],r['error']) not in ((128,0),(-1,11))): errors.append('syscall_truth'); continue
            if r['phase'] and (r['begin_ns']<resumed[0]['time_ns'] or r['returned']!=128): errors.append('recovery_failed')
            if not r['phase'] and r['end_ns']>restored['time_ns']: errors.append('restore_before_pressure_completed')
            failures+=r['returned']==-1
            if report is None: continue
            match=[e for e in episodes if e['cookie']==r['cookie'] and
                   r['begin_ns']<=e['begin_ns']<=(e['terminal_ns'] or 0)<=r['end_ns']]
            if len(match)!=1: errors.append('send_identity_or_bracket'); continue
            e=match[0]; found.append(e)
            if (not e['skb_address'] or e['outcome'] not in ('ADMITTED','MEMORY_ADMISSION_REJECTED')
                    or e['packet_payload_owner']!='UNKNOWN' or e['blocking_container'] is not None
                    or e['allocator_lock_holder'] is not None): errors.append('wrong_attribution')
            if e['outcome']=='MEMORY_ADMISSION_REJECTED':
                rejected+=1
                if (r['phase'] or r['returned']!=-1 or not
                    e['backend_interval_ns'][1]<=(e['release_entry_ns'] or 0)<=e['terminal_ns']):
                    errors.append('reject_release_order')
            elif not e['terminal_ns']<=(e['release_entry_ns'] or 0)<=window['end_ns']:
                errors.append('queued_header_not_released')
        if case=='txadmission':
            if not failures or report is not None and not rejected: errors.append('missing_native_rejection')
        elif failures or rejected: errors.append('normal_budget_failure')
        participants.append(dict(actor=actor,eligible=24,captured=len(found),failed_sends=failures,
                                 admission_rejected=rejected,recovery_sends=8))
    if report is not None and (report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS'
                              or report['tx']['status']!='PASS' or report['tx']['excluded'] or report['tx']['unknown']
                              or any(s['waits'] for s in report['sockets']) or len(report['tx']['episodes'])!=48): errors.append('capture_quality')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,participants=participants,
                scope='native repair-mode queue acceptance and budget rejection; no wire-delivery claim',
                performance_certification='NOT_ACCEPTED')
