# SPDX-License-Identifier: GPL-2.0
"""NUMA placement truth is not proof of an allocator blocker."""
from owner_report import fields

CASES=('local','remote','split')


def nodes(case):
    if case not in CASES: raise ValueError('placement case')
    return [0,0] if case=='local' else [1,1] if case=='remote' else [0,1]


def case_order():
    return ['%s-%s%d'%(case,mode,r) for case in CASES for r in range(3)
            for mode in (('off','allocator') if r%2==0 else ('allocator','off'))]


def check_case(case,window,logs,report=None,identities=None,require_releases=True):
    if len(logs)!=2 or not require_releases: raise ValueError('two actors and release truth required')
    errors=[]; participants=[]; captured=0; caches=set()
    for i,log in enumerate(logs):
        pids=[fields(v).get('host_pid') for v in log.splitlines() if v.startswith('CIS_SESSION_CONTAINER ')]
        truth=[fields(v) for v in log.splitlines() if v.startswith('CIS_ALLOC_PLACEMENT ')]
        if len(pids)!=1 or not pids[0] or [r.get('index') for r in truth]!=list(range(8)):
            errors.append('truth_count_'+str(i)); continue
        calls=[]; released=[]
        if report is not None:
            identity=identities[i]
            calls=[c for c in report['calls'] if c['actor'][:2]==[identity['id'],identity['generation']]
                   and c['actor'][2]&0xffffffff==pids[0]]
            if len(calls)!=8: errors.append('actor_call_count_'+str(i))
        found=[]
        for r in truth:
            wanted=nodes(case)[i]
            if (r.get('cpu')!=i or r.get('requested_node')!=wanted or r.get('allowed_node')!=wanted
                    or r.get('actual_node')!=wanted or r.get('result')!=0 or not r.get('object') or not r.get('cache')
                    or not window['start_ns']<=r.get('begin_ns',-1)<r.get('allocated_ns',-1)<=r.get('release_begin_ns',-1)<r.get('end_ns',-1)<=window['end_ns']):
                errors.append('placement_truth_%d_%s'%(i,r.get('index'))); continue
            caches.add(r['cache'])
            if report is None: continue
            match=[c for c in calls if r['begin_ns']<=c['interval_ns'][0]<c['interval_ns'][1]<=r['allocated_ns']]
            if len(match)!=1:
                errors.append('call_interval_%d_%d'%(i,r['index'])); continue
            c=match[0]; found.append(c)
            if (c['cache_address']!=r['cache'] or c['object_address']!=r['object'] or c['requested_node']!=wanted
                    or c['sample_shift']!=0 or c['operation']!='single' or c['requested']!=1 or c['returned_count']!=1
                    or c['rolled_back_count'] or wanted not in c['observed_nodes'] or c.get('holder') is not None):
                errors.append('source_placement_%d_%d'%(i,r['index']))
            releases=[v for v in report['lifetimes']['release_entries'] if v['allocation_requester']==c['actor']
                      and v['observation_key']['call_ns']==c['call_ns'] and v['object_address']==r['object']
                      and r['release_begin_ns']<=v['release_entry_ns']<=r['end_ns']]
            if len(releases)!=1 or releases[0]['release_cpu']!=i or releases[0].get('blocking_container') is not None:
                errors.append('release_%d_%d'%(i,r['index']))
            released.extend(releases)
        captured+=len(found)
        participants.append(dict(actor=i,requested_node=nodes(case)[i],truth_calls=len(truth),captured_calls=len(found),releases=len(released)))
    if len(caches)!=1: errors.append('cache_identity')
    if report is not None and (report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS'
                               or report['excluded'] or report['lifetimes']['status']!='PASS'):
        errors.append('capture_quality')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,participants=participants,eligible=16,captured=captured,
        selected_call_recall=captured/16 if report is not None else None,
        scope='explicit allowed NUMA placement in a two-node VM; not exhaustion, general cpuset guarantees or causal interference',
        performance_certification='NOT_ACCEPTED')
