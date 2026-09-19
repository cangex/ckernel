# SPDX-License-Identifier: GPL-2.0
"""Join observer output to native API timestamps, not to generated events."""
from owner_report import fields

def truth(log):
    rows=[fields(v) for v in log.splitlines() if v.startswith('CIS_RWSEM_TRUTH ')]
    if len(rows)!=1: raise ValueError('one native truth record required')
    r=rows[0]
    keys={'reset','slot','token','object','task','mode','hold_ms','enter_ns','acquired_ns','release_ns','end_ns','outcome'}
    if not keys<=r.keys() or r['reset'] not in (0,1) or not r['object'] or not r['task']:
        raise ValueError('invalid fixture truth')
    if not 0<r['enter_ns']<=r['end_ns']: raise ValueError('invalid native timing')
    if not r['reset']:
        if r['outcome']==1 and not r['enter_ns']<=r['acquired_ns']<=r['release_ns']<=r['end_ns']:
            raise ValueError('invalid hold timing')
        if r['outcome'] not in (0,1,-4): raise ValueError('unexpected native outcome')
        if r['outcome']!=1 and (r['acquired_ns'] or r['release_ns']): raise ValueError('failed acquire claims hold')
    return r


def check(report, jobs, logs, identities, case, window):
    errors=[]; operations=[]; resets=[]
    for job in jobs:
        r=truth(logs[job['log']]); args=job['arguments']; actor=identities[job['actor_index']]
        if (r['token']!=job['token'] or r['slot']!=args.get('slot',0) or r['mode']!=args.get('mode',0) or
            r['hold_ms']!=args.get('hold',0) or bool(r['reset'])!=bool(args.get('reset',False))):
            errors.append('fixture_arguments')
        r['identity']=[actor['id'],actor['generation']]
        (resets if r['reset'] else operations).append(r)
    if not operations: errors.append('no_business_operations')
    if not report: return dict(status='FAIL' if errors else 'OFF_VALID',errors=errors,operations=len(operations))
    if report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS': errors.append('capture_quality')
    if any(r['end_ns']>window['end_ns'] for r in operations): errors.append('truth_outside_window')
    if case!='preWindow' and any(r['enter_ns']<window['start_ns'] for r in operations+resets):
        errors.append('truth_before_window')
    positive=case not in ('private','tryFailure','nonOwner','preWindow','overflow')
    expected=[]; eligible=[]
    for w in operations:
        if w['mode'] in (2,3,4): continue
        wmode='write' if w['mode'] in (1,5) else 'read'
        end=w['acquired_ns'] or w['end_ns']
        for h in operations:
            if h['outcome']!=1 or h['mode']==4 or (h['object'],h['token'])!=(w['object'],w['token']) or h['task']==w['task']: continue
            hmode='write' if h['mode'] in (1,3) else 'read'
            if wmode==hmode=='read': continue
            overlap=min(end,h['release_ns'])-max(w['enter_ns'],h['acquired_ns'])
            if overlap<=0: continue
            pair=(w['object'],w['token'],w['task'],h['task'],hmode)
            expected.append(pair)
            if positive and overlap>=1_000_000: eligible.append(pair)
    captured=set(); e2=[]
    objects={r['object'] for r in operations}
    observed=[obj for obj in report['objects'] if obj['address'] in objects]
    if not observed or not any(obj.get('waits') for obj in observed): errors.append('no_observed_fixture_operations')
    if case=='overflow' and not any(obj.get('unknown',{}).get('reader_capacity',0)>0 for obj in observed):
        errors.append('reader_overflow_not_observed')
    if case=='nonOwner' and not any(obj.get('unknown',{}).get('non_owner_api',0)>0 for obj in observed):
        errors.append('non_owner_api_not_observed')
    if case=='preWindow' and not any(obj.get('init_ns')==0 and obj.get('waits') for obj in observed):
        errors.append('pre_window_unknown_not_observed')
    if case=='tryFailure' and not any(w.get('outcome')=='try_failed' for obj in observed for w in obj.get('waits',[])):
        errors.append('try_failure_not_observed')
    for obj in report['objects']:
        if obj['address'] not in objects: continue
        generations=[r for r in resets if r['object']==obj['address'] and r['enter_ns']<=obj['init_ns']<=r['end_ns']]
        token=generations[0]['token'] if len(generations)==1 else None
        for wait in obj['waits']:
            for holder in wait['observed_holders']:
                if holder['evidence']!='E2': continue
                e2.append(holder)
                pair=(obj['address'],token,wait['waiter'][2],holder['holder'][2],holder['mode'])
                if pair not in expected: errors.append('wrong_holder_or_lifetime')
                else:
                    wr=next(r for r in operations if r['task']==pair[2] and r['token']==token)
                    hr=next(r for r in operations if r['task']==pair[3] and r['token']==token)
                    if wait['waiter'][:2]!=wr['identity'] or holder['holder'][:2]!=hr['identity']: errors.append('wrong_container')
                    if not max(wr['enter_ns'],hr['enter_ns'])<=holder['interval_ns'][0]<holder['interval_ns'][1]<=min(wr['end_ns'],hr['end_ns']):
                        errors.append('unsupported_holder_interval')
                    captured.add(pair)
    if not positive and e2: errors.append('negative_case_promoted')
    if positive and not eligible: errors.append('no_eligible_truth')
    if positive and len(set(eligible)&captured)/max(1,len(set(eligible)))<.90: errors.append('eligible_recall')
    if case=='abort' and not any(r['outcome']==-4 for r in operations): errors.append('missing_abort')
    if case=='tryFailure' and not any(r['outcome']==0 for r in operations): errors.append('missing_try_failure')
    if case=='reuse' and len({r['token'] for r in operations})!=2: errors.append('missing_reuse')
    return dict(status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),operations=len(operations),
        eligible=len(set(eligible)),captured_eligible=len(set(eligible)&captured),e2_edges=len(e2),
        population='predeclared fixture native hold/attempt overlaps >=1ms, not all kernel operations',
        private_objects=(case=='private'),causal='NOT_CLAIMED')
