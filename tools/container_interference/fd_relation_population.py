# SPDX-License-Identifier: GPL-2.0
"""Full independent acquisition/inner-hold overlap population, not spin truth."""
import json

from fd_population_check import check_population, POPULATION_PLAN


RELATION_PLAN = dict(
    schema='cis-fd-relation-population-v1',
    unit='ordered fixture acquisition-attempt and other-task inner-hold overlap',
    eligibility='all successful calls wholly in window; same files and lock; different tasks; positive outer-attempt/inner-hold overlap',
    selection='no observed-event, prefix, duration-threshold or sampled-edge selection',
    minimum_capture_ratio=0.90,
    boundary='not pure spin, actual blocking duration, causal delay or arbitrary-lock recall',
)


def check_relations(logs, raw, window, case, report, plan=None):
    if plan is not None and plan != RELATION_PLAN:
        raise ValueError('FD relation population plan changed')
    population=check_population(logs,raw,window,case,POPULATION_PLAN)
    errors=list(population['errors'])
    if report['quality']['status']!='PASS': errors.append('capture_quality')
    if report.get('omitted_findings',0) or report.get('finding_count',len(report['findings']))!=len(report['findings']):
        errors.append('incomplete_relation_audit')
    calls=[json.loads(line.split(' ',1)[1]) for text in logs for line in text.splitlines()
           if line.startswith('CIS_FD_TRUTH ')]
    if len(calls)>256 or len(report['findings'])>4096:
        raise ValueError('FD relation population capacity')
    edges=[e for e in report['findings'] if e.get('resource')=='files_struct_lock']
    if case=='native':
        return dict(status='FAIL' if errors else 'PASS_SCOPED',errors=sorted(set(errors)),
                    eligible=None,captured=None,capture_ratio=None,threshold_status='UNAVAILABLE_NATIVE',
                    true_blocking_recall=None,plan=RELATION_PLAN)
    if errors:
        return dict(status='FAIL',errors=sorted(set(errors)),eligible=None,captured=None,
                    capture_ratio=None,threshold_status='INVALID_TRUTH_OR_CAPTURE',true_blocking_recall=None)
    # Fixed 256-call bound; enumerate truth pairs before consulting any edge.
    eligible={}
    for wi,w in enumerate(calls):
        for hi,h in enumerate(calls):
            if ((w['object'],w['files'])!=(h['object'],h['files']) or
                    (w['tgid'],w['tid'])==(h['tgid'],h['tid'])):
                continue
            lo=max(w['begin_ns'],h['acquired_ns'])
            end=min(w['acquired_ns'],h['release_begin_ns'])
            if lo<end: eligible[(wi,hi)]=(lo,end)
    captured=set()
    def same(actor,q):
        return actor[0]==q['cgroup_id'] and actor[2]==(q['tgid']<<32)|q['tid']
    for edge in edges:
        obj=int(edge['object'],16)
        matching=[]
        for wi,hi in eligible:
            w,h=calls[wi],calls[hi]
            if (w['object']==obj and same(edge['waiter'],w) and same(edge['holder'],h) and
                    w['begin_ns']<=edge['wait_begin_ns']<edge['wait_end_ns']<=w['acquired_ns'] and
                    h['begin_ns']<=edge['begin_ns']<edge['end_ns']<=h['released_ns']):
                matching.append((wi,hi))
        if len(matching)!=1:
            errors.append('relation_not_in_independent_population')
        elif matching[0] in captured:
            errors.append('duplicate_relation_for_truth_pair')
        else:
            captured.add(matching[0])
    missing=sorted(set(eligible)-captured)
    ratio=len(captured)/len(eligible) if eligible else None
    threshold=('PASS' if ratio>=RELATION_PLAN['minimum_capture_ratio'] else 'FAIL') if eligible else 'VALID_NEGATIVE'
    # Historical data gets a retrospective result, not a rewritten acceptance.
    if plan is not None and threshold=='FAIL': errors.append('predeclared_relation_coverage')
    return dict(schema='cis-fd-relation-population-result-v1',
                status='FAIL' if errors else 'PASS_SCOPED',errors=sorted(set(errors)),
                design='PREDECLARED' if plan is not None else 'RETROSPECTIVE_REPLAY',plan=RELATION_PLAN,
                eligible=len(eligible),captured=len(captured),capture_ratio=ratio,
                missing_pairs=[dict(waiter_call=w,holder_call=h) for w,h in missing],
                threshold_status=threshold,true_blocking_recall=None,
                boundary=RELATION_PLAN['boundary'])
