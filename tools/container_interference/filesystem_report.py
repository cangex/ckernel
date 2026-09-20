# SPDX-License-Identifier: GPL-2.0
"""Selected native filesystem operations, not an invented journal lock owner."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from collector_audit import audit
from explain import explain, within_window
from owner_report import fields

OPERATIONS={1:'journal_commit_check',2:'transaction_switch_wait',3:'allocation_group_use',
            4:'legacy_orphan_add',5:'legacy_orphan_delete',6:'orphan_file_operation'}
MAX_EPISODES=4096


def analyze(record,raw):
    if record.get('collector')!='filesystem' or len(raw)>16<<20:
        raise ValueError('bounded filesystem capture required')
    base=explain(record,raw); scope=audit(record,raw)
    selected=scope.get('filesystem_selection') or {}
    known={(v['id'],v['generation']) for v in record.get('root_identities',{}).values()}
    episodes=[]; seen=set(); excluded=Counter(); stacks={}; participants=defaultdict(set)
    for line in raw.decode().splitlines():
        row=json.loads(line); d=fields(row.get('detail',''))
        if row.get('kind')=='stack_symbols' and ' leaf_to_root=' in row.get('detail',''):
            stacks[d['stack_id']]=row['detail'].split(' leaf_to_root=',1)[1].split('>')
        if row.get('kind')!='FILESYSTEM': continue
        required={'protocol','begin_ns','acquired_ns','end_ns','tid','task_start','cgroup_id','cpu',
                  'resource','lease','dev','operation','sample_shift','value','count','error','stack_id'}
        if (not required<=d.keys() or any(type(d[k]) is not int for k in required) or
                d['protocol']!=1 or d['operation'] not in OPERATIONS or not 0<=d['cpu']<512 or
                d['sample_shift']!=(0 if d['operation']<=2 else 4) or
                min(d['resource'],d['lease'],d['tid'],d['task_start'],d['cgroup_id'])<=0 or
                d['lease']!=selected.get('lease') or d['dev']!=selected.get('dev') or
                min(d['value'],d['count'])<0 or not -4095<=d['error']<=0 or
                not 0<d['begin_ns']<=d['end_ns'] or
                (d['operation'] in (4,5) and not d['begin_ns']<=d['acquired_ns']<=d['end_ns']) or
                (d['operation'] not in (4,5) and d['acquired_ns']!=0)):
            excluded['schema_or_selection']+=1; continue
        actor=[row.get('id'),row.get('generation'),d['tid'],d['task_start']]
        if tuple(actor[:2]) not in known or not within_window(record,d['begin_ns'],d['end_ns']):
            excluded['identity_or_window']+=1; continue
        key=(*actor,d['begin_ns'],d['resource'],d['operation'])
        if key in seen: excluded['duplicate']+=1; continue
        seen.add(key)
        if len(episodes)>=MAX_EPISODES: excluded['capacity']+=1; continue
        family=('journal_transaction' if d['operation']<=2 else 'allocation_group' if d['operation']==3
                else 'legacy_orphan_mutex' if d['operation'] in (4,5) else 'orphan_file')
        resource=dict(kind=family,address=d['resource'],lease=d['lease'],dev=d['dev'],
                      value=d['value'] if d['operation']<=3 else None)
        e=dict(actor=actor,resource=resource,operation=OPERATIONS[d['operation']],
            interval_ns=[d['begin_ns'],d['end_ns']],acquired_ns=d['acquired_ns'] or None,
            value=d['value'],count=d['count'],sample_shift=d['sample_shift'],error=d['error'],
            stack_id=d['stack_id'],evidence='E1',holder=None,blocking_container=None,
            wait_condition_observed=d['operation']<=2 and d['count']>0,
            lock_contention='NOT_ESTABLISHED',spin_cycles=None)
        if d['operation'] in (4,5):
            e['acquire_bracket_wall_ns']=d['acquired_ns']-d['begin_ns']
        episodes.append(e)
    quality=base['quality']
    if excluded or scope['status']!='PASS':
        quality=dict(quality,status='FAIL' if excluded or scope['status']=='FAIL' else 'BLOCKED',
                     defects=quality['defects']+['filesystem_audit'])
    for e in episodes:
        e['stack_leaf_to_root']=stacks.get(e.pop('stack_id'),[])
        if quality['status']!='PASS': e['evidence']='UNACCEPTED'
        else:
            k=json.dumps(e['resource'],sort_keys=True)
            participants[k].add(tuple(e['actor'][:2]))
    shared=[dict(resource=json.loads(k),containers=[list(x) for x in sorted(v)],evidence='E1',
                 relation='same_public_resource_observed',contention='NOT_ESTABLISHED',blocking_container=None)
            for k,v in sorted(participants.items()) if len(v)>1]
    return dict(schema='cis-filesystem-report-v1',quality=quality,scope_audit=scope,source=base['source'],
        analysis_source_sha256=dict(base['analysis_source_sha256'],
            filesystem_report=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()),
        raw_sha256=hashlib.sha256(raw).hexdigest(),episodes=episodes,shared_resources=shared,excluded=dict(excluded),
        coverage=dict(observation_status='ACCEPTED_SAMPLES' if episodes and quality['status']=='PASS' else 'NO_ACCEPTED_SAMPLES',
            operations={n:sum(e['operation']==n for e in episodes) for n in OPERATIONS.values()},
            waits=sum(e['wait_condition_observed'] for e in episodes),orphan_add_error_cleanup='NOT_TRACED',
            allocation_group_lock_holders='UNKNOWN',commit_worker_exclusive_owner='NOT_INFERRED',
            uncompleted_operations='UNKNOWN',read_only_image_cache='NOT_INFERRED'),
        limits=['private directories can share a journal; sharing is not proof of one tenant blocking another',
                'commit/switch brackets include lock, wakeup and scheduling cost, not pure sleep or spin cycles',
                'zero commit-wait iterations is not a wait; group use is not group-lock contention',
                'legacy orphan mutex and orphan-file operations are different feature-dependent mechanisms',
                'sampled acquisition bracket does not identify every holder or prove a contended mutex',
                'objects are scoped to pinned filesystem lease and short window, not lifetime beyond that lease',
                'source audit includes non-target callers, filters and unfinished operations; sampling is not unbiased',
                'unregistered background and asynchronous ownership remain unknown; no cross-collector time sum'])
