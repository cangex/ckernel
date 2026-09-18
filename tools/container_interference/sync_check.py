# SPDX-License-Identifier: GPL-2.0
"""Check E1 object/actor/interval candidates against isolated fixture truth.

No recall estimate: qspinlock does not emit a pair for every contended acquisition.
No ownership result is inferred from fixture truth or fed into the collector.
"""
import json


def check(report, logs, expected_positive=False):
    truth=[]
    for text in logs:
        for line in text.splitlines():
            if line.startswith('CIS_SYNC_TRUTH '): truth.append(json.loads(line.split(' ',1)[1]))
    objects={row['object'] for row in truth}
    matched=[];errors=[]
    for event in report['candidates']:
        obj=int(event['address'],0)
        if obj not in objects: continue
        begin,end=event['interval_ns'];tid=event['task_id']&0xffffffff
        matches=[row for row in truth if row['result']==0 and row['operation']!=3 and
                 row['object']==obj and row['tid']==tid and row['cgroup_id']==event['container_id'] and
                 row['begin_ns']<=begin<=end<=row['acquired_ns']]
        if len(matches)!=1: errors.append(dict(reason='object_actor_or_interval_mismatch',event=event,matches=len(matches)))
        else: matched.append(dict(object=obj,generation=matches[0]['generation'],tid=tid,
                                  container=event['container_id'],access=event['access_class'],interval_ns=[begin,end]))
        if event['holder'] is not None or event['other_container_identified']:
            errors.append(dict(reason='unsupported_owner_inference',event=event))
    if not truth: errors.append(dict(reason='missing_fixture_truth'))
    if expected_positive and not matched: errors.append(dict(reason='positive_fixture_not_observed'))
    if report['quality']['status']!='PASS': errors.append(dict(reason='capture_quality',quality=report['quality']))
    return dict(schema='cis-sync-fixture-check-v1',status='FAIL' if errors else 'PASS',
                truth_operations=len(truth),matched_intervals=len(matched),matches=matched,errors=errors,
                false_observed_relations=len(errors),eligible_recall=None,holder_coverage='NOT_IMPLEMENTED',
                scope='first-layer discovery only; truth is never used to manufacture an owner edge')
