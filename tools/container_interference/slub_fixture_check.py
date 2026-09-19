# SPDX-License-Identifier: GPL-2.0
"""Independent native-lock oracle; no inference from a cache name alone."""
from owner_report import fields, analyze


def truth(text):
    rows=[fields(line) for line in text.splitlines() if line.startswith('CIS_SLUB_TRUTH ')]
    if len(rows)!=1: raise ValueError('one native oracle record required')
    r=rows[0]
    required={'command','hold_us','wait_node','wait_holders','mode','token','node','task','cache',
              'object','begin_ns','acquired_ns','release_ns','end_ns','outcome'}
    if not required<=r.keys() or r['command'] not in (1,2,3) or not r['task'] or not r['token']:
        raise ValueError('invalid oracle schema')
    if r['command']==2:
        if not r['cache'] or not 0<r['begin_ns']<=r['end_ns'] or r['outcome']!=1:
            raise ValueError('invalid native operation')
        if r['mode']==0 and (not r['object'] or not r['begin_ns']<=r['acquired_ns']<=r['release_ns']<=r['end_ns']):
            raise ValueError('invalid node hold')
        if r['mode']==1 and (r['object'] or r['acquired_ns'] or r['release_ns']):
            raise ValueError('ordinary allocation not a holder oracle')
    return r


def check(events, jobs, logs, identities, case, window):
    errors=[]; operations=[]
    for job in jobs:
        r=truth(logs[job['log']]); args=job['arguments']
        expected=dict(command={'reset':1,'operate':2,'recreate':3}[args['command']],token=job['token'],
            node=args['node'],hold_us=args['hold'],wait_node=args['wait_node'],wait_holders=args['wait_holders'],mode=args['mode'])
        if any(r[k]!=v for k,v in expected.items()): errors.append('oracle_arguments')
        r['identity']=[identities[job['actor_index']][k] for k in ('id','generation')]
        if r['command']==2: operations.append(r)
    if not operations: errors.append('no_operations')
    if events is None:
        return dict(status='FAIL' if errors else 'OFF_VALID',errors=errors,operations=len(operations))
    if any(not window['start_ns']<=r['begin_ns']<=r['end_ns']<=window['end_ns'] for r in operations):
        errors.append('truth_outside_window')
    report=analyze(events)
    if report['loss_or_recursion_gap'] or report['cache_identity_errors']: errors.append('source_or_identity_gap')
    owner_rows=[fields(e['detail']) for e in events if e.get('kind')=='OWNER']
    caches={r['cache'] for r in operations}
    if not owner_rows or not any(e.get('resource')==4 and e.get('cache') in caches for e in owner_rows):
        errors.append('no_native_node_events')
    expected=[]; eligible=[]; captured=set()
    for w in operations:
        if w['mode']: continue
        for h in operations:
            if h['mode'] or h['task']==w['task'] or (w['cache'],w['object'],w['token'])!=(h['cache'],h['object'],h['token']): continue
            overlap=min(w['acquired_ns'],h['release_ns'])-max(w['begin_ns'],h['acquired_ns'])
            if overlap<=0: continue
            pair=(w['cache'],w['object'],w['token'],w['task'],h['task'])
            expected.append((pair,w,h))
            if overlap>=100_000: eligible.append(pair)
    for edge in report['edges']:
        if edge['level']!='E2': continue
        if edge['resource']!='slub_node_list_lock': errors.append('wrong_resource'); continue
        if case=='native':
            # This bridge observes production call sites. There is no independently
            # timed node-lock oracle here, so no recall/holder correctness credit.
            continue
        matches=[(p,w,h) for p,w,h in expected if
            p[0]==int(edge['cache_address'],16) and p[1]==int(edge['object'],16) and
            p[3]==edge['waiter'][2] and p[4]==edge['holder'][2] and
            w['begin_ns']<=edge['wait_begin_ns']<=edge['wait_end_ns']<=w['end_ns'] and
            h['acquired_ns']<=edge['begin_ns']<edge['end_ns']<=h['release_ns']]
        if len(matches)!=1: errors.append('wrong_holder_object_or_lifetime'); continue
        pair,w,h=matches[0]
        if list(edge['waiter'][:2])!=w['identity'] or list(edge['holder'][:2])!=h['identity']:
            errors.append('wrong_container'); continue
        captured.add(pair)
    if case=='private' and report['edges']: errors.append('private_nodes_promoted')
    if case=='unseenHolder':
        if report['edges']: errors.append('unobserved_acquire_promoted')
        if not eligible or not report['incomplete_intervals']: errors.append('unobserved_acquire_not_exercised')
    positive=case in ('shared','switch','recreate')
    if positive and not eligible: errors.append('no_eligible_overlap')
    if positive and len(set(eligible)&captured)/max(1,len(set(eligible)))<.9: errors.append('eligible_recall')
    if case=='switch' and len({h['identity'][0] for _,_,h in expected})!=2: errors.append('holder_switch_missing')
    if case=='recreate' and len({r['token'] for r in operations})!=2: errors.append('recreation_missing')
    reused=case=='recreate' and len({r['object'] for r in operations})<len({r['token'] for r in operations})
    return dict(status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),operations=len(operations),
        eligible=len(set(eligible)),captured_eligible=len(set(eligible)&captured),edges=len(report['edges']),
        same_address_reuse_observed=reused,lifecycle_boundaries=report['lifecycle_boundaries'],
        unobserved_acquire_negative=(case=='unseenHolder'),
        ordinary_native_bridge=(case=='native'),native_holder_truth=(case!='native'),
        scope='fixture overlaps >=100us; native bridge has no holder-recall credit; no causal or production claim')
