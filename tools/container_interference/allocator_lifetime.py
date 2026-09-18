# SPDX-License-Identifier: GPL-2.0
"""Observed allocation instance to release-entry join; never by freeing current."""
from collections import Counter
import json
from owner_report import fields
from explain import within_window


def correlate(record,raw,report,stacks):
    objects, releases, excluded = {}, [], Counter()
    known={(v['id'],v['generation']) for v in record.get('root_identities',{}).values()}
    supported='alloc_release' in record.get('inventory',{}).get('program_names',[])
    accepted=report['quality']['status']=='PASS' and report['scope_audit']['status']=='PASS'
    for call in report['calls']:
        for obj in call['object_samples']:
            key=(*call['actor'],call['call_ns'],call['cache_address'],obj['object'],obj['time_ns'],obj['ordinal'])
            if key in objects: raise ValueError('duplicate observed allocation instance')
            if len(objects)>=1024:
                excluded['object_capacity']+=1
                continue
            objects[key]=(call,obj)
    required={'protocol','sample_time_ns','call_ns','allocation_time_ns','allocation_ordinal','tid','task_start',
              'cpu','cache','object','context','caller','stack_id','executor_tid','executor_start','executor_id','executor_generation'}
    seen=set()
    for line in raw.decode().splitlines():
        item=json.loads(line)
        if item.get('kind')!='ALLOC_RELEASE': continue
        d=fields(item.get('detail',''))
        if (not required<=d.keys() or any(type(d[k]) is not int or d[k]<0 for k in required-{'stack_id'})
                or d['stack_id'] < -1 or d['protocol']!=1 or d['context'] not in (0,1,2)):
            excluded['schema']+=1; continue
        key=(item.get('id'),item.get('generation'),d['tid'],d['task_start'],d['call_ns'],d['cache'],
             d['object'],d['allocation_time_ns'],d['allocation_ordinal'])
        if not accepted or not supported or key not in objects:
            excluded['no_complete_allocation']+=1; continue
        if key in seen:
            excluded['duplicate_release']+=1; continue
        call,obj=objects[key]
        if (not within_window(record,d['allocation_time_ns'],d['sample_time_ns'])
                or d['sample_time_ns']<=d['allocation_time_ns']
                or call['returned_count'] and d['sample_time_ns']<call['interval_ns'][1]):
            excluded['lifetime_order']+=1; continue
        executor=(d['executor_id'],d['executor_generation'])
        if (d['context'] and any(d[k] for k in ('executor_tid','executor_start','executor_id','executor_generation'))
                or not d['context'] and (not d['executor_tid'] or not d['executor_start'])
                or executor!=(0,0) and executor not in known):
            excluded['executor_identity']+=1; continue
        seen.add(key)
        releases.append(dict(object_address=d['object'],cache_address=d['cache'],evidence='E2',
            observation_key=dict(boot_id=record.get('boot_id'),session_id=record.get('session_id'),
                                 call_ns=d['call_ns'],ordinal=d['allocation_ordinal']),
            allocation_requester=call['actor'],allocation_time_ns=d['allocation_time_ns'],
            allocation_cpu=obj['cpu'],release_entry_ns=d['sample_time_ns'],release_cpu=d['cpu'],
            observed_age_ns=d['sample_time_ns']-d['allocation_time_ns'],
            allocation_state='returned' if call['returned_count'] else 'rolled_back',
            release_executor=dict(container=list(executor) if executor!=(0,0) else None,
                tid=d['executor_tid'] or None,task_start=d['executor_start'] or None,
                context=('task','softirq','hardirq')[d['context']]),
            release_stack_leaf_to_root=stacks.get(d['stack_id'],[]),release_caller=d['caller'],
            release_completed='UNOBSERVED',rcu_grace_period='UNOBSERVED',blocking_container=None))
    return dict(status='FAIL' if excluded else 'PASS' if supported and accepted else 'UNOBSERVED',
        release_entries=releases,excluded=dict(excluded),allocations_without_release=len(objects)-len(seen),
        completion='entry before native release/reuse, not completion; no mutation of allocator ownership',
        unknown_semantics=['memcg billing','Maple tree owner','RCU grace-period start/end','allocator free backend cost'])
