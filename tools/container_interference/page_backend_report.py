# SPDX-License-Identifier: GPL-2.0
"""Native page-zone brackets, not an inferred lock owner or page lifetime."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from collector_audit import audit
from explain import explain, within_window
from owner_report import fields

OPERATIONS={1:'pcp_refill',2:'pcp_drain',3:'buddy_allocate',4:'buddy_free'}
MAX_EPISODES=4096


def analyze(record,raw):
    if record.get('collector')!='page_backend' or len(raw)>16<<20:
        raise ValueError('bounded page backend capture required')
    base=explain(record,raw); scope=audit(record,raw)
    known={(v['id'],v['generation']) for v in record.get('root_identities',{}).values()}
    episodes=[]; seen=set(); stacks={}; excluded=Counter(); participants=defaultdict(set)
    selected=record.get('backend_selection') or dict(cache='page_zone',nodes=[])
    for line in raw.decode().splitlines():
        item=json.loads(line); d=fields(item.get('detail',''))
        if item.get('kind')=='stack_symbols' and ' leaf_to_root=' in item.get('detail',''):
            stacks[d['stack_id']]=item['detail'].split(' leaf_to_root=',1)[1].split('>')
        if item.get('kind')!='PAGE_BACKEND': continue
        required={'protocol','begin_ns','acquired_ns','releasing_ns','end_ns','tid','task_start',
                  'cgroup_id','cpu','zone','node','zone_index','order','operation','sample_shift',
                  'requested_pages','completed_pages','stack_id'}
        if (not required<=d.keys() or any(type(d[k]) is not int for k in required) or
                d['protocol']!=1 or d['operation'] not in OPERATIONS or
                not 0<=d['sample_shift']<=16 or not 0<=d['node']<1024 or not 0<=d['zone_index']<8 or
                not 0<=d['cpu']<512 or not -1<=d['order']<64 or
                min(d['tid'],d['task_start'],d['cgroup_id'],d['zone'])<=0 or
                min(d['requested_pages'],d['completed_pages'])<0 or not 0<d['begin_ns']<=d['acquired_ns']<=d['releasing_ns']<=d['end_ns'] or
                selected['nodes'] and d['node'] not in selected['nodes']):
            excluded['schema_or_selection']+=1; continue
        if ((d['operation']==2)!=(d['order']==-1) or
                d['operation']!=2 and d['completed_pages']>d['requested_pages']):
            excluded['schema_or_selection']+=1; continue
        actor=[item.get('id'),item.get('generation'),d['tid'],d['task_start']]
        if tuple(actor[:2]) not in known or not within_window(record,d['begin_ns'],d['end_ns']):
            excluded['identity_or_window']+=1; continue
        key=(*actor,d['begin_ns'],d['zone'])
        if key in seen: excluded['duplicate']+=1; continue
        seen.add(key)
        if len(episodes)>=MAX_EPISODES: excluded['capacity']+=1; continue
        episodes.append(dict(actor=actor,cgroup_id_at_endpoints=d['cgroup_id'],zone_address=d['zone'],
            node=d['node'],zone_index=d['zone_index'],operation=OPERATIONS[d['operation']],
            order=d['order'],requested_pages=d['requested_pages'],completed_pages=d['completed_pages'],
            interval_ns=[d['begin_ns'],d['end_ns']],acquired_ns=d['acquired_ns'],releasing_ns=d['releasing_ns'],
            wait_to_acquire_wall_ns=d['acquired_ns']-d['begin_ns'],
            held_inner_wall_ns=d['releasing_ns']-d['acquired_ns'],
            after_release_wall_ns=d['end_ns']-d['releasing_ns'],sample_shift=d['sample_shift'],
            stack_id=d['stack_id'],evidence='E1',holder=None,blocking_container=None,spin_cycles=None))
    quality=base['quality']
    if excluded or scope['status']!='PASS':
        quality=dict(quality,status='FAIL' if excluded or scope['status']=='FAIL' else 'BLOCKED',
                     defects=quality['defects']+['page_backend_audit'])
    for e in episodes:
        e['stack_leaf_to_root']=stacks.get(e.pop('stack_id'),[])
        if quality['status']!='PASS': e['evidence']='UNACCEPTED'
        else: participants[e['zone_address'],e['node'],e['zone_index']].add(tuple(e['actor'][:2]))
    shared=[dict(zone_address=k[0],node=k[1],zone_index=k[2],containers=[list(a) for a in sorted(v)],
                 evidence='E1',relation='same_zone_backend_observed',holder=None,
                 contention='NOT_ESTABLISHED',lifetime='operation_boundaries_only')
            for k,v in sorted(participants.items()) if len(v)>1]
    return dict(schema='cis-page-backend-report-v1',quality=quality,scope_audit=scope,
        source=base['source'],raw_sha256=hashlib.sha256(raw).hexdigest(),
        analysis_source_sha256=dict(base['analysis_source_sha256'],
            page_backend_report=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()),
        episodes=episodes,shared_backends=shared,excluded=dict(excluded),
        coverage=dict(pcp_refill='SAMPLED',pcp_drain='SAMPLED',buddy_allocate='SAMPLED',buddy_free='SAMPLED',
                      observed_operation_counts={name:sum(e['operation']==name for e in episodes) for name in OPERATIONS.values()},
                      observation_status='ACCEPTED_SAMPLES' if episodes and quality['status']=='PASS' else 'NO_ACCEPTED_SAMPLES',
                      other_zone_lock_users='NOT_TRACED',holder='UNKNOWN',page_lifetime='NOT_TRACKED',causal='NOT_CLAIMED'),
        limits=['wall brackets include timing overhead, preemption and interrupts; not pure spin cycles',
                'one callback follows zone unlock; callers may still hold another native lock or have IRQs disabled',
                'same NUMA zone participation is not proof of contention or a uniquely blocking tenant',
                'per-CPU systematic sampling is not unbiased; do not extrapolate counts into population cost',
                'cgroup identity checked at endpoints, not a complete migration history',
                'unregistered background release executors remain unknown, not charged to an arbitrary container',
                'zone address lifetime outside an observed operation is not certified; other zone lock holders remain unknown'])
