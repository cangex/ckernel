# SPDX-License-Identifier: GPL-2.0
"""Bounded sampled-ancestor drilldown; this is not live population aggregation."""
from collections import Counter
import uuid

MAX_OBJECTS=64
MAX_ACTORS=8
FIELDS={'usage','children_min_usage','children_low_usage'}


def aggregate(report, selection):
    if report.get('schema')!='cis-counter-report-v1' or report.get('quality',{}).get('status')!='PASS':
        raise ValueError('accepted counter report required')
    scope=report.get('object_scope',{})
    boot=scope.get('boot_id')
    if not isinstance(boot,str) or str(uuid.UUID(boot))!=boot:
        raise ValueError('boot-qualified object scope required')
    if selection.get('boot_id')!=boot or str(selection.get('session_id'))!=str(scope.get('session_id')):
        raise ValueError('selection from another boot or capture')
    selected=selection.get('objects')
    if not isinstance(selected,list) or not 1<=len(selected)<=MAX_OBJECTS:
        raise ValueError('selected object capacity')
    groups={}
    for item in selected:
        if (not isinstance(item,dict) or set(item)!={'address','generation','field'} or
                type(item['address']) is not int or item['address']<=0 or
                type(item['generation']) is not int or not 0<item['generation']<2**63 or
                item['field'] not in FIELDS): raise ValueError('initialized object key required')
        key=item['address'],item['generation'],item['field']
        if key in groups: raise ValueError('duplicate selection')
        groups[key]=dict(key=item,actors={},omitted_actor_steps=0)
    for call in report['calls']:
        touched={}
        for step in call['steps']:
            field='children_min_usage' if step['stage']=='children_min_update' else 'children_low_usage' if step['stage']=='children_low_update' else 'usage'
            key=step['address'],step['object_generation'],field
            if key not in groups: continue
            group=groups[key]; actor=tuple(call['actor'][:2])
            if actor not in group['actors']:
                if len(group['actors'])>=MAX_ACTORS:
                    group['omitted_actor_steps']+=1; continue
                group['actors'][actor]=dict(update_stages=Counter(),native_quantity=Counter(),
                    sampled_calls=0,failed_calls=0,call_wall_ns_log2=Counter(),stacks=[])
            value=group['actors'][actor]
            value['update_stages'][step['stage']]+=1
            value['native_quantity'][step['stage']]+=step['pages']
            touched[key]=value
        # One sampled call can update an ancestor repeatedly during rollback.
        # Its wall time enters this ancestor's distribution once, not per step.
        for value in touched.values():
            value['sampled_calls']+=1; value['failed_calls']+=call['outcome']=='limit_failed'
            value['call_wall_ns_log2'][call['elapsed_wall_ns'].bit_length()]+=1
            stack=call['stack_leaf_to_root']
            if stack and stack not in value['stacks'] and len(value['stacks'])<4: value['stacks'].append(stack)
    result=[]
    for group in groups.values():
        actors=[]
        for actor,value in sorted(group['actors'].items()):
            actors.append(dict(container=list(actor),**{k:dict(v) if isinstance(v,Counter) else v for k,v in value.items()}))
        result.append(dict(key=group['key'],actors=actors,omitted_actor_steps=group['omitted_actor_steps'],
            status='TRUNCATED' if group['omitted_actor_steps'] else 'OBSERVED' if actors else 'NOT_OBSERVED',
            relation='shared_counter_updates' if len(actors)>1 else 'single_observed_participant' if actors else None,
            evidence='E2' if actors else None,holder=None,cacheline_contention='UNVERIFIED'))
    return dict(schema='cis-counter-drilldown-v1',object_scope=scope,objects=result,
        input_raw_sha256=report['raw_sha256'],count_scope='complete sampled calls only; not population counts',
        time_scope='whole sampled call wall time, not ancestor-only atomic latency; overlapping objects must not be summed',
        histogram='bucket k represents 2^(k-1)..2^k-1 ns; k=0 is zero',
        live_source_aggregation='NOT_IMPLEMENTED',performance_certification='NOT_ACCEPTED')
