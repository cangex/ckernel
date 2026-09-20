# SPDX-License-Identifier: GPL-2.0
"""Sampled participation and pressure at one pinned public queue, not ownership."""
from collections import Counter, defaultdict
import hashlib
import json

from collector_audit import audit
from explain import explain, within_window
from owner_report import fields

MAX_SAMPLES=8192
KEYS=set(('protocol begin_ns acquired_ns end_ns lease qdisc txq dev skb actor_cgroup '
          'socket_cgroup txq_state netns ifindex queue handle operation sample_shift '
          'qlen_begin qlen_end backlog_begin backlog_end length context flags packets result '
          'actor_id actor_generation socket_id socket_generation tid task_start cpu').split())


def analyze(record,raw):
    if record.get('collector')!='qdisc' or len(raw)>16<<20:
        raise ValueError('bounded qdisc capture required')
    base=explain(record,raw); scope=audit(record,raw)
    selection=scope.get('queue_selection') or {}
    identities=dict(record.get('root_identities',{})); identities.update(record.get('owner_identities',{}))
    known={(v['id'],v['generation']) for v in identities.values()}
    rows=[]; excluded=Counter(); seen=set(); objects=set()
    for line in raw.decode().splitlines():
        row=json.loads(line)
        if row.get('kind')!='QDISC': continue
        d=fields(row.get('detail',''))
        if (set(d)!=KEYS or any(type(d[k]) is not int for k in KEYS) or
                any(d[k]<0 for k in KEYS-{'result'}) or
                d['protocol']!=1 or d['operation'] not in (1,2) or d['sample_shift']!=4 or
                d['context'] not in (0,1) or not 0<=d['cpu']<512 or
                min(d[k] for k in ('lease','qdisc','txq','dev','skb'))<=0 or
                any(d[k]!=selection.get(k) for k in ('lease','qdisc','netns','ifindex','queue','handle')) or
                d['packets']!=(1 if d['operation']==2 else 0) or not within_window(record,d['begin_ns'],d['end_ns']) or
                d['end_ns']>=record['window']['end_ns'] or
                (d['operation']==1 and d['acquired_ns'] and not d['begin_ns']<=d['acquired_ns']<=d['end_ns']) or
                (d['operation']==2 and d['acquired_ns']!=0)):
            excluded['schema_or_selection']+=1; continue
        actor=(d['actor_id'],d['actor_generation']); billing=(d['socket_id'],d['socket_generation'])
        if (actor!=(0,0) and actor not in known or billing!=(0,0) and billing not in known or
                d['context'] and (actor!=(0,0) or d['tid'] or d['task_start'] or d['actor_cgroup']) or
                actor!=(0,0) and not (d['tid'] and d['task_start'] and d['actor_cgroup']) or
                billing!=(0,0) and not d['socket_cgroup']):
            excluded['identity']+=1; continue
        key=(d['cpu'],d['operation'],d['begin_ns'],d['end_ns'],d['skb'])
        if key in seen: excluded['duplicate']+=1; continue
        seen.add(key)
        if len(rows)>=MAX_SAMPLES: excluded['capacity']+=1; continue
        objects.add((d['txq'],d['dev']))
        rows.append(dict(sample=d,actor=list(actor) if actor!=(0,0) else None,
            socket_accounting=list(billing) if billing!=(0,0) else None,
            operation='admission' if d['operation']==1 else 'service_point',evidence='E1',
            backlog_observed=bool(d['qlen_begin'] or d['qlen_end'] or d['backlog_begin'] or d['backlog_end']),
            acquire_bracket_wall_ns=d['acquired_ns']-d['begin_ns'] if d['acquired_ns'] else None,
            holder=None,blocking_container=None,packet_owner=None,wire_completion=False))
    if len(objects)>1: excluded['lease_object_changed']+=1
    quality=base['quality']
    if excluded or scope['status']!='PASS':
        quality=dict(quality,status='FAIL' if excluded or scope['status']=='FAIL' else 'BLOCKED',
                     defects=quality['defects']+['queue_audit'])
    participants=defaultdict(set)
    for r in rows:
        if quality['status']!='PASS': r['evidence']='UNACCEPTED'
        else:
            if r['actor']: participants['executor'].add(tuple(r['actor']))
            if r['socket_accounting']: participants['socket_accounting'].add(tuple(r['socket_accounting']))
    shared=[dict(resource=selection,role=k,containers=[list(v) for v in sorted(values)],
                 evidence='E1',relation='same_pinned_queue_participation',blocking_container=None,
                 lock_contention='NOT_ESTABLISHED') for k,values in sorted(participants.items()) if len(values)>1]
    return dict(schema='cis-public-queue-report-v1',quality=quality,scope_audit=scope,
        source=base['source'],raw_sha256=hashlib.sha256(raw).hexdigest(),samples=rows,
        shared_resources=shared,excluded=dict(excluded),coverage=dict(
            observation_status='ACCEPTED_SAMPLES' if rows and quality['status']=='PASS' else 'NO_ACCEPTED_SAMPLES',
            admission_samples=sum(r['operation']=='admission' for r in rows),
            service_samples=sum(r['operation']=='service_point' for r in rows),
            backlog_samples=sum(r['backlog_observed'] for r in rows),
            unknown_executors=sum(r['actor'] is None for r in rows),
            unknown_socket_accounting=sum(r['socket_accounting'] is None for r in rows),
            wire_completion='NOT_OBSERVED',driver_completion='NOT_OBSERVED',
            lock_holder='NOT_INFERRED',percpu_occupancy_aggregate='NOT_AVAILABLE'),
        limits=['admission bracket includes busy/root lock, enqueue and service; not pure spin or packet residence',
                'one sampled head per service call, no skb lifetime or clone/forward lineage; do not join skb addresses',
                'accounting root is not payload owner; descendant or retired socket accounting remains unknown',
                'queue sharing and backlog do not identify a blocking container; no E2 holder or E3 cause',
                'raw qlen/backlog snapshots are not aggregate occupancy for per-CPU qdisc stats',
                'device and qdisc identity pinned per lease; class/filter administration frozen by contract',
                'entry budget includes native filtering and sampling; source-off tested separately'])
