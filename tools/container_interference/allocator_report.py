# SPDX-License-Identifier: GPL-2.0
"""Sampled native allocation stages, not inferred allocator lock holders."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from collector_audit import audit
from explain import explain, within_window
from owner_report import fields

STAGES = {1:'begin',2:'pre_begin',3:'pre_end',4:'slow_begin',5:'slow_end',6:'cpu_fast',
          7:'cpu_partial',8:'partial_begin',9:'partial_end',10:'node_wait',11:'node_held',
          12:'node_done',13:'new_begin',14:'new_end',15:'post_begin',16:'post_end',
          17:'bulk_item',18:'bulk_rollback',19:'kfence',20:'end',21:'node_release'}
PAIRS = {2:(3,'pre_hook'),4:(5,'slow_helper'),8:(9,'node_partial'),
         10:(11,'node_lock_acquire'),11:(12,'node_lock_section'),
         13:(14,'new_slab'),15:(16,'post_hook')}
PRIORITY = ['node_lock_acquire','node_lock_held_observed','node_lock_unlock',
            'node_lock_section','pre_hook','post_hook','new_slab','node_partial','slow_helper']
MAX_CALLS = 1024


def allocation_result(rows):
    last=rows[-1]
    if last['count']:
        return dict(status='RETURNED',failure_region=None,cause=None)
    if len(rows)==4 and [r['stage'] for r in rows]==[1,2,3,20] and not rows[2]['count']:
        region='pre_allocation_hook'
    elif any(r['stage']==18 for r in rows):
        region='bulk_rollback'
    else:
        region='backend_or_post_hook'
    return dict(status='FAILED',failure_region=region,cause='UNKNOWN')


def stages(rows, begin, end):
    opened, intervals = {}, []
    pairs=dict(PAIRS)
    if any(row['stage']==21 for row in rows):
        pairs[11]=(21,'node_lock_held_observed')
        pairs[21]=(12,'node_lock_unlock')
    for row in rows:
        stage = row['stage']
        ending = [first for first,(last,_) in pairs.items() if last==stage]
        for first in ending:
            if first not in opened: raise ValueError('unpaired stage end')
            start = opened.pop(first)
            if first in (10,11,21) and (not row['resource'] or start['resource']!=row['resource']):
                raise ValueError('node lock address changed')
            intervals.append(dict(kind=pairs[first][1],begin_ns=start['sample_time_ns'],
                end_ns=row['sample_time_ns'],resource=start['resource'],evidence='E1',holder=None))
        if stage in pairs:
            if stage in opened: raise ValueError('duplicate stage begin')
            opened[stage]=row
    if opened: raise ValueError('unclosed stage')
    boundaries=sorted({begin,end} | {v[k] for v in intervals for k in ('begin_ns','end_ns')})
    exclusive=Counter()
    for left,right in zip(boundaries,boundaries[1:]):
        covering={v['kind'] for v in intervals if v['begin_ns']<=left and right<=v['end_ns']}
        chosen=next((k for k in PRIORITY if k in covering),'unclassified')
        exclusive[chosen]+=right-left
    if sum(exclusive.values())!=end-begin: raise ValueError('invalid interval partition')
    return intervals,dict(exclusive)


def analyze(record, raw):
    if record.get('collector')!='allocator' or len(raw)>16<<20:
        raise ValueError('bounded allocator capture required')
    base=explain(record,raw); groups=defaultdict(list); stacks={}; excluded=Counter()
    known={(v['id'],v['generation']) for v in record.get('root_identities',{}).values()}
    for line in raw.decode().splitlines():
        item=json.loads(line); d=fields(item.get('detail',''))
        if item.get('kind')=='stack_symbols' and ' leaf_to_root=' in item.get('detail',''):
            stacks[d['stack_id']]=item['detail'].split(' leaf_to_root=',1)[1].split('>')
        if item.get('kind')!='ALLOCATOR': continue
        required={'protocol','sample_time_ns','call_ns','tid','task_start','cpu','cache','object','resource',
                  'operation','stage','ordinal','gfp','requested','count','requested_node','observed_node','sample_shift','stack_id'}
        if (not required<=d.keys() or d['protocol']!=1 or d['operation'] not in (1,2) or
                d['stage'] not in STAGES or not 0<=d['sample_shift']<=16 or
                any(type(d[k]) is not int or d[k]<0 for k in required-{'requested_node','observed_node','stack_id'}) or
                any(type(d[k]) is not int or d[k] < -1 for k in ('requested_node','observed_node')) or
                type(d['stack_id']) is not int or d['stack_id'] < -4095):
            excluded['schema']+=1; continue
        who=item.get('id'),item.get('generation'),d['tid'],d['task_start']
        if who[:2] not in known or not all(who) or not d['cache'] or not d['requested']:
            excluded['unknown_identity_or_cache']+=1; continue
        key=(*who,d['call_ns'])
        if key not in groups and len(groups)>=MAX_CALLS:
            excluded['capacity']+=1; continue
        groups[key].append(d)
    if excluded['schema']:
        base['quality']=dict(base['quality'],status='FAIL',defects=base['quality']['defects']+['allocator_schema'])
    calls=[]; stack_errors=Counter()
    for key,rows in groups.items():
        rows.sort(key=lambda r:r['ordinal']); first,last=rows[0],rows[-1]
        stable=('cache','operation','requested','gfp','requested_node','sample_shift','stack_id')
        if (base['quality']['status']!='PASS' or first['stage']!=1 or last['stage']!=20 or
                last['ordinal']>64 or [r['ordinal'] for r in rows]!=list(range(len(rows))) or
                any(r['stage'] in (1,20) for r in rows[1:-1]) or
                any(any(r[k]!=first[k] for k in stable) for r in rows) or
                any(a['sample_time_ns']>b['sample_time_ns'] for a,b in zip(rows,rows[1:])) or
                key[-1]>first['sample_time_ns'] or not within_window(record,key[-1],last['sample_time_ns']) or
                last['count'] not in (0,first['requested']) or first['operation']==1 and first['requested']!=1 or
                first['operation']==1 and bool(last['object'])!=bool(last['count'])):
            excluded['incomplete_or_unaccepted_call']+=1; continue
        try: intervals,partition=stages(rows[1:-1],key[-1],last['sample_time_ns'])
        except ValueError:
            excluded['stage_pairing']+=1; continue
        rollbacks=[r['count'] for r in rows if r['stage']==18]
        if len(rollbacks)>1 or rollbacks and (last['count'] or rollbacks[0]>=first['requested']):
            excluded['rollback']+=1; continue
        stack_id=first['stack_id']
        chain=stacks.get(stack_id,[]) if stack_id>=0 else []
        if stack_id<0:
            stack_errors[str(stack_id)]+=1
        calls.append(dict(actor=list(key[:4]),call_ns=key[-1],evidence='E1',cache_address=first['cache'],
            operation='single' if first['operation']==1 else 'bulk',requested=first['requested'],
            result=allocation_result(rows),
            returned_count=last['count'],rolled_back_count=rollbacks[0] if rollbacks else 0,
            object_address=last['object'] or None,requested_node=first['requested_node'],
            observed_nodes=sorted({r['observed_node'] for r in rows if r['observed_node']>=0}),
            interval_ns=[key[-1],last['sample_time_ns']],elapsed_wall_ns=last['sample_time_ns']-key[-1],
            phases=intervals,exclusive_wall_ns=partition,visits=dict(Counter(STAGES[r['stage']] for r in rows)),
            sample_shift=first['sample_shift'],stack_id=stack_id,stack_leaf_to_root=chain,
            allocation_stack_error=stack_id if stack_id<0 else None,
            allocation_stack_status='AVAILABLE' if chain else 'UNAVAILABLE',
            allocation_owner=list(key[:2]),free_owner='UNOBSERVED',cache_lifetime='UNKNOWN',holder=None,spin_cycles=None,
            object_samples=[dict(object=r['object'],time_ns=r['sample_time_ns'],ordinal=r['ordinal'],cpu=r['cpu'])
                            for r in rows if r['object'] and (r['stage']==17 or r['stage']==20 and first['operation']==1 and last['count']==1)]))
    result=dict(schema='cis-allocator-report-v1',quality=base['quality'],scope_audit=audit(record,raw),
        source=base['source'],raw_sha256=hashlib.sha256(raw).hexdigest(),
        analysis_source_sha256=dict(base['analysis_source_sha256'],**{name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ('allocator_report.py','allocator_lifetime.py')}),
        calls=calls,excluded=dict(excluded),allocation_stack_errors=dict(stack_errors),
        allocation_stack_errors_scope='completed accepted calls, not repeated stage records',
        performance_certification='NOT_ACCEPTED',
        partition_priority=PRIORITY+['unclassified'],
        limits=['phase wall time includes observer and preemption, not atomic or spin cycles',
                'exclusive partition avoids adding nested slow/partial/node-lock intervals twice',
                'node_lock_acquire includes uncontended calls; no full lock owner/lifetime coverage',
                'node_lock_section ends after unlock and is not a pure held interval or holder attribution',
                'node_lock_held_observed is an inner held bracket, not full lock hold time or population holder coverage',
                'node_lock_unlock includes the release observer and native unlock, potentially post-unlock scheduling',
                'failure region identifies an observed control-flow boundary, not another container or a specific ENOMEM cause',
                'same cache address is not proof of interference or a shared allocation owner',
                'sampling is per CPU selected-cache entry, not unbiased population cost',
                'stack helper errors retain typed stages but do not establish a complete calling path',
                'release entry is not allocator completion or RCU grace-period duration',
                'allocation identity is the registered requesting container, not proof of memcg billing owner',
                'no Maple tree identity or hardware cache-line cause is asserted'])
    from allocator_lifetime import correlate
    result['lifetimes']=correlate(record,raw,result,stacks)
    return result
