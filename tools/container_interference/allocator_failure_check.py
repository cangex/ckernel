# SPDX-License-Identifier: GPL-2.0
"""Independent native failslab truth; a failed request is not a lock holder."""
from owner_report import fields

CASES=('single','bulk','private','bystander','recovery')
SETTINGS={'probability':'100','interval':'1','times':'-1','space':'0','verbose':'0',
          'task-filter':'Y','ignore-gfp-wait':'N','cache-filter':'Y'}


def case_order():
    return ['%s-%s%d'%(case,mode,r) for case in CASES for r in range(3)
            for mode in (('off','allocator') if r%2==0 else ('allocator','off'))]


def expected(case,actor,index):
    if case not in CASES: raise ValueError('failure case')
    cache=int(case=='private' and actor==1)
    armed=int((case!='bystander' or actor==0) and (case!='recovery' or index%2==0))
    count=8 if case=='bulk' else 1
    return cache,armed,count,0 if armed and not cache else count


def check_case(case,window,logs,report=None,identities=None,require_releases=True):
    if len(logs)!=2 or not require_releases: raise ValueError('two actors and release truth required')
    errors=[]; participants=[]; captured=eligible=failed=0; caches={}
    for actor,log in enumerate(logs):
        pids=[fields(v).get('host_pid') for v in log.splitlines() if v.startswith('CIS_SESSION_CONTAINER ')]
        truth=[fields(v) for v in log.splitlines() if v.startswith('CIS_ALLOC_FAILURE ')]
        objects=[fields(v) for v in log.splitlines() if v.startswith('CIS_ALLOC_FAILURE_OBJECT ')]
        if len(pids)!=1 or not pids[0] or [r.get('index') for r in truth]!=list(range(8)):
            errors.append('truth_count_'+str(actor)); continue
        if any(v.get('index') not in range(8) for v in objects): errors.append('object_index_'+str(actor))
        cache=expected(case,actor,0)[0]
        eligible+=0 if cache else 8
        calls=[]; found=[]; released=[]
        if report is not None:
            identity=identities[actor]
            calls=[c for c in report['calls'] if c['actor'][:2]==[identity['id'],identity['generation']]
                   and c['actor'][2]&0xffffffff==pids[0]]
            if len(calls)!=(0 if cache else 8): errors.append('actor_call_count_'+str(actor))
        for r in truth:
            index=r['index']; cache,armed,count,returned=expected(case,actor,index)
            allocated=[v['object'] for v in objects if v.get('index')==index]
            if [v.get('ordinal') for v in objects if v.get('index')==index]!=list(range(returned)):
                errors.append('object_ordinals_%d_%d'%(actor,index))
            if (r.get('cache')!=cache or r.get('armed')!=armed or r.get('count')!=count or
                    r.get('bulk')!=int(case=='bulk') or r.get('returned')!=returned or r.get('result')!=0 or
                    r.get('cpu')!=actor or not r.get('cache_address') or
                    len(allocated)!=returned or len(set(allocated))!=returned or any(not v for v in allocated) or
                    not window['start_ns']<=r.get('begin_ns',-1)<r.get('end_ns',-1)<=window['end_ns']):
                errors.append('truth_%d_%d'%(actor,index)); continue
            if returned:
                if not r['end_ns']<=r.get('release_begin_ns',-1)<r.get('release_end_ns',-1)<=window['end_ns']:
                    errors.append('release_truth_%d_%d'%(actor,index))
            elif r.get('release_begin_ns')!=0 or r.get('release_end_ns')!=0:
                errors.append('failed_request_has_release_%d_%d'%(actor,index))
            caches.setdefault(cache,set()).add(r['cache_address'])
            if cache or report is None: continue
            match=[c for c in calls if r['begin_ns']<=c['interval_ns'][0]<c['interval_ns'][1]<=r['end_ns']]
            if len(match)!=1:
                errors.append('call_interval_%d_%d'%(actor,index)); continue
            c=match[0]; found.append(c); failed+=int(not returned)
            if (c['cache_address']!=r['cache_address'] or c['sample_shift']!=0 or
                    c['operation']!=('bulk' if case=='bulk' else 'single') or c['requested']!=count or
                    c['returned_count']!=returned or c['rolled_back_count']!=0 or c.get('holder') is not None or
                    c.get('blocking_container') is not None or (not returned and c['object_address'] is not None)):
                errors.append('source_result_%d_%d'%(actor,index))
            if not returned and (set(c['visits'])!={'begin','pre_begin','pre_end','end'} or c['object_samples']):
                errors.append('injected_prehook_path_%d_%d'%(actor,index))
            frees=[v for v in report['lifetimes']['release_entries'] if v['allocation_requester']==c['actor']
                   and v['observation_key']['call_ns']==c['call_ns']]
            if (len(frees)!=returned or sorted(v['object_address'] for v in frees)!=sorted(allocated) or
                    any(not r['release_begin_ns']<=v['release_entry_ns']<=r['release_end_ns'] or
                        v['release_cpu']!=actor or v.get('blocking_container') is not None for v in frees)):
                errors.append('release_%d_%d'%(actor,index))
            released.extend(frees)
        captured+=len(found)
        participants.append(dict(actor=actor,private_cache=bool(cache),truth_calls=len(truth),
                                 captured_calls=len(found),releases=len(released)))
    if any(len(v)!=1 for v in caches.values()) or (case=='private' and
            (set(caches)!={0,1} or caches[0]==caches[1])): errors.append('cache_identity')
    if report is not None and (report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS' or
            report['excluded'] or report['lifetimes']['status']!='PASS'): errors.append('capture_quality')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,participants=participants,eligible=eligible,
                captured=captured,failed_calls=failed,selected_call_recall=captured/eligible if report is not None else None,
                scope='native failslab pre-hook failures, cache/task isolation and recovery; not real pressure or partial bulk rollback',
                performance_certification='NOT_ACCEPTED')
