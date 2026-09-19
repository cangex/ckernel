# SPDX-License-Identifier: GPL-2.0
"""Native bulk prefix rollback against caller-array truth, not inferred pressure."""
from owner_report import fields

CASES=('partial','unmarked')
SETTINGS={'probability':'100','interval':'1','times':'-1','space':'0','verbose':'0',
          'task-filter':'Y','ignore-gfp-wait':'N','ignore-gfp-highmem':'N','min-order':'0'}


def case_order():
    return ['%s-%s%d'%(case,mode,r) for case in CASES for r in range(3)
            for mode in (('off','allocator') if r%2==0 else ('allocator','off'))]


def check_case(case,window,logs,report=None,identities=None,require_releases=True):
    if case not in CASES or len(logs)!=2 or not require_releases:
        raise ValueError('fixed rollback case and two actors required')
    errors=[]; captured=rolled_back=0; participants=[]; caches=[]
    for actor,log in enumerate(logs):
        pids=[fields(v).get('host_pid') for v in log.splitlines() if v.startswith('CIS_SESSION_CONTAINER ')]
        rows=[fields(v) for v in log.splitlines() if v.startswith('CIS_ALLOC_ROLLBACK ')]
        if len(pids)!=1 or not pids[0] or [r.get('index') for r in rows]!=list(range(4)):
            errors.append('truth_count_'+str(actor)); continue
        if [r.get('action') for r in rows]!=[1,2,2,3]: errors.append('truth_actions_'+str(actor))
        if any(a.get('end_ns',0)>b.get('begin_ns',0) for a,b in zip(rows,rows[1:])):
            errors.append('truth_order_'+str(actor))
        addresses={r.get('cache_address') for r in rows}
        if len(addresses)!=1 or None in addresses or 0 in addresses: errors.append('cache_identity_'+str(actor))
        caches.append(addresses)
        calls=[]; releases=[]
        if report is not None:
            identity=identities[actor]
            calls=[c for c in report['calls'] if c['actor'][:2]==[identity['id'],identity['generation']]
                   and c['actor'][2]&0xffffffff==pids[0]]
            if len(calls)!=(4 if actor==0 else 0): errors.append('selected_calls_'+str(actor))
        matched=[]
        for r in rows:
            index=r['index']; armed=int(case=='partial' and actor==0 and index==1)
            objects=[r.get('object%d'%i) for i in range(4)]
            if (r.get('cache')!=actor or r.get('armed')!=armed or r.get('cpu')!=actor or
                    not window['start_ns']<=r.get('begin_ns',-1)<r.get('end_ns',-1)<=window['end_ns'] or
                    any(type(o) is not int or o<0 for o in objects)):
                errors.append('truth_boundary_%d_%d'%(actor,index)); continue
            if index in (1,2):
                populated=[o for o in objects if o]
                if (len(set(populated))!=len(populated) or r.get('populated')!=len(populated) or
                        objects!=populated+[0]*(4-len(populated)) or
                        (armed and (r.get('returned')!=0 or not 0<len(populated)<4)) or
                        (not armed and (r.get('returned')!=4 or len(populated)!=4))):
                    errors.append('truth_result_%d_%d'%(actor,index))
            elif (r.get('returned') or r.get('populated') or not objects[0] or
                  index==0 and (not objects[1] or objects[0]==objects[1]) or
                  index==0 and any(objects[2:]) or
                  index==3 and (objects[0]!=rows[0].get('object0') or any(objects[1:]))):
                errors.append('truth_seed_%d_%d'%(actor,index))
            if report is None or actor: continue
            group=[c for c in calls if r['begin_ns']<=c['interval_ns'][0]<c['interval_ns'][1]<=r['end_ns']]
            if len(group)!=(2 if index==0 else 1 if index in (1,2) else 0):
                errors.append('call_interval_%d'%index); continue
            matched.extend(group)
            if index==0:
                if sorted(c['object_address'] for c in group)!=sorted(objects[:2]): errors.append('seed_objects')
                if any(c['cache_address']!=r['cache_address'] or c['sample_shift']!=0 or
                       c['operation']!='single' or c['requested']!=1 or c['returned_count']!=1 or
                       c['rolled_back_count'] or c['result']['status']!='RETURNED' for c in group):
                    errors.append('seed_source')
                continue
            if not group: continue
            c=group[0]; expected=set(o for o in objects if o)
            if (c['cache_address']!=r['cache_address'] or c['sample_shift']!=0 or c['operation']!='bulk' or
                    c['requested']!=4 or c['returned_count']!=r['returned'] or
                    c['rolled_back_count']!=(len(expected) if armed else 0) or
                    {v['object'] for v in c['object_samples']}!=expected or
                    c['result']['status']!=('FAILED' if armed else 'RETURNED') or
                    c['result']['failure_region']!=('bulk_rollback' if armed else None) or
                    c.get('holder') is not None or c.get('blocking_container') is not None):
                errors.append('source_result_'+str(index))
            if armed and (not c['visits'].get('new_begin') or not c['visits'].get('bulk_rollback') or
                          c['result'].get('cause')!='UNKNOWN'): errors.append('failure_path')
            frees=[v for v in report['lifetimes']['release_entries'] if v['allocation_requester']==c['actor']
                   and v['observation_key']['call_ns']==c['call_ns']]
            if (len(frees)!=len(expected) or {v['object_address'] for v in frees}!=expected or
                    any(not r['begin_ns']<=v['release_entry_ns']<=r['end_ns'] or
                        v['allocation_state']!=('rolled_back' if armed else 'returned') or
                        v['release_cpu']!=actor or v.get('blocking_container') is not None for v in frees)):
                errors.append('prefix_release_'+str(index))
            releases.extend(frees); rolled_back+=len(expected) if armed else 0
        captured+=len(matched)
        participants.append(dict(actor=actor,selected=actor==0,operations=rows,captured_calls=len(matched),
                                 bulk_release_entries=len(releases)))
    if len(caches)!=2 or caches[0]&caches[1]: errors.append('private_cache_isolation')
    if report is not None and (report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS' or
            report['excluded'] or report['lifetimes']['status']!='PASS' or
            report['lifetimes']['allocations_without_release']): errors.append('capture_quality')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,eligible=4,captured=captured,
                rolled_back_objects=rolled_back,participants=participants,
                scope='native task-filtered page-allocation fault and actual partial bulk rollback; not natural pressure or lock attribution',
                performance_certification='NOT_ACCEPTED')
