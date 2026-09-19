#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Observed rwsem holders, not owner-field guesses or complete reader census."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from collector_audit import audit
from explain import explain, within_window
from owner_report import fields

MAX_READERS = 8


def union_ns(intervals):
    total, end = 0, 0
    for a, b in sorted(intervals):
        total += max(0, b-max(a, end)); end = max(end, b)
    return total


def reconstruct(rows, known, stacks):
    """At most 64 watched objects, 1024 records/object from the live contract."""
    groups = defaultdict(list)
    for row in rows: groups[row['object'], row['init_ns']].append(row)
    if len({a for a, _ in groups}) > 64: raise ValueError('object capacity')
    result = []
    for (address, epoch), events in sorted(groups.items()):
        if len(events) > 1024: raise ValueError('event capacity')
        events.sort(key=lambda r:r['sample_time_ns'])
        init = [r for r in events if r['phase']==1]
        if epoch and (len(init)!=1 or init[0]['sample_time_ns']!=epoch or events[0]!=init[0]):
            raise ValueError('unproven initialization identity')
        if not epoch and init: raise ValueError('zero initialization')
        active, pending, holds, attempts, downgrading = {}, {}, [], [], set()
        unknown = Counter(); tainted = False

        def close(task, r, mode):
            h = active.pop(task, None)
            if h is None:
                unknown['acquire_not_observed'] += 1; return
            if h['mode'] != mode: raise ValueError('release type mismatch')
            h['end_ns'] = r['sample_time_ns']
            h['release_actor'] = [r[k] for k in ('actor_id','actor_generation','actor_tid','actor_start')]
            holds.append(h)

        for r in events:
            phase, now = r['phase'], r['sample_time_ns']
            actor = [r[k] for k in ('actor_id','actor_generation','actor_tid','actor_start')]
            task = tuple(actor[2:])
            if phase==1: continue
            if phase in (10,11):
                unknown['non_owner_api'] += 1; tainted = True; continue
            if phase in (2,3,14,15):
                if task in pending: raise ValueError('nested attempt on same object')
                pending[task] = dict(actor=actor, mode='read' if phase in (2,14) else 'write',
                    start_ns=now, trylock=phase in (14,15), stack_id=r['stack_id'])
            elif phase in (4,5,8,9,16):
                p = pending.pop(task, None)
                if p:
                    expected = 'read' if phase in (4,8) else 'write' if phase in (5,9) else p['mode']
                    if expected!=p['mode']: raise ValueError('attempt type mismatch')
                    if phase==16 and not p['trylock']: raise ValueError('try failure without try')
                    p.update(end_ns=now,outcome='acquired' if phase in (4,5) else 'try_failed' if phase==16 else 'aborted')
                    attempts.append(p)
                else:
                    unknown['begin_not_observed'] += 1
                    if epoch: tainted=True
                if phase in (4,5):
                    mode = 'read' if phase==4 else 'write'
                    if task in active: raise ValueError('duplicate holder')
                    if mode=='write' and active or mode=='read' and any(h['mode']=='write' for h in active.values()):
                        raise ValueError('impossible observed holder overlap')
                    if len(active)>=MAX_READERS:
                        tainted=True; unknown['reader_capacity']+=1
                    else: active[task]=dict(actor=actor,mode=mode,start_ns=now)
            elif phase in (6,7,12):
                if phase==12:
                    if task not in active: tainted=True
                    downgrading.add(task)
                close(task,r,'read' if phase==6 else 'write')
            elif phase==13:
                if task not in downgrading:
                    tainted=True; unknown['downgrade_begin_not_observed']+=1
                downgrading.discard(task)
                if task in active: raise ValueError('duplicate downgraded reader')
                if len(active)>=MAX_READERS: tainted=True; unknown['reader_capacity']+=1
                else: active[task]=dict(actor=actor,mode='read',start_ns=now)
        unknown['unclosed_holds'] += len(active)
        unknown['unfinished_attempts'] += len(pending)
        unknown['unfinished_downgrade'] += len(downgrading)
        waits=[]
        for p in attempts:
            pairs=[]
            if not p['trylock']:
                for h in holds:
                    a,b=max(p['start_ns'],h['start_ns']),min(p['end_ns'],h['end_ns'])
                    if a>=b or h['actor'][2:]==p['actor'][2:] or p['mode']==h['mode']=='read': continue
                    accepted = bool(epoch and not tainted and tuple(h['actor'][:2]) in known and
                                    tuple(p['actor'][:2]) in known)
                    pairs.append(dict(holder=h['actor'],mode=h['mode'],interval_ns=[a,b],
                        evidence='E2' if accepted else 'E1',
                        relation_scope='unknown' if not accepted else 'cross_container' if h['actor'][:2]!=p['actor'][:2] else 'container_internal'))
            explained=union_ns([h['interval_ns'] for h in pairs if h['evidence']=='E2'])
            waits.append(dict(waiter=p['actor'],mode=p['mode'],interval_ns=[p['start_ns'],p['end_ns']],
                operation='try' if p['trylock'] else 'acquire',outcome=p['outcome'],observed_holders=pairs,
                unexplained_elapsed_ns=p['end_ns']-p['start_ns']-explained,spin_cycles=None,
                stack_leaf_to_root=stacks.get(p['stack_id'],[]),causal='NOT_ESTABLISHED'))
        result.append(dict(address=address,init_ns=epoch,lifetime='OBSERVED_INIT' if epoch else 'UNKNOWN',
            waits=waits,holds=holds,unknown=dict(unknown),reader_set_complete=False,
            attribution_eligible=bool(epoch and not tainted)))
    return result


def analyze(record, raw):
    if record.get('collector')!='rwsem': raise ValueError('rwsem collector required')
    base=explain(record,raw); scope=audit(record,raw); rows=[]; stacks={}; defects=[]
    known={(r['id'],r['generation']) for r in record.get('owner_identities',{}).values()}
    known.update((r['id'],r['generation']) for r in record.get('root_identities',{}).values())
    required={'protocol','sample_time_ns','object','init_ns','phase','actor_tid','actor_start',
              'actor_id','actor_generation','cpu','skipped','stack_id'}
    for line in raw.splitlines():
        item=json.loads(line); d=fields(item.get('detail',''))
        if item.get('kind')=='stack_symbols' and ' leaf_to_root=' in item.get('detail',''):
            stacks[d['stack_id']]=item['detail'].split(' leaf_to_root=',1)[1].split('>')
        if item.get('kind')!='RWSEM': continue
        if (not required<=d.keys() or d['protocol']!=1 or not 1<=d['phase']<=16 or
                not d['object'] or not d['actor_tid'] or not d['actor_start'] or d['init_ns']<0 or
                d['init_ns']>d['sample_time_ns'] or (not d['actor_id'])!= (not d['actor_generation']) or
                not within_window(record,d['sample_time_ns'],d['sample_time_ns'])):
            defects.append('rwsem_schema_or_window'); continue
        if len(rows)>=65536: defects.append('rwsem_capacity'); break
        rows.append(d)
    maps=scope['counters'].get('owner_map_updates',{})
    if any(maps.get(k) for k in ('watch_failed','attempt_failed')): defects.append('rwsem_watch_or_event_capacity')
    objects=[]
    if base['quality']['status']=='PASS' and scope['status']=='PASS' and not defects:
        try: objects=reconstruct(rows,known,stacks)
        except ValueError as error: defects.append('rwsem_sequence:'+str(error))
    quality=base['quality']
    if defects: quality=dict(quality,status='FAIL',defects=quality['defects']+defects)
    return dict(schema='cis-rwsem-report-v1',quality=quality,scope_audit=scope,objects=objects,
        source=base['source'],raw_sha256=hashlib.sha256(raw).hexdigest(),
        analysis_source_sha256=dict(base['analysis_source_sha256'],**{'rwsem_report.py':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}),
        limits=['only supported public non-RT rwsem APIs; no arbitrary semaphore or RT claim',
            'E2 requires an observed initialization in this capture; static/pre-window objects remain E1',
            'at most eight observed active readers; non-owner API or overflow disables E2 for that lifetime',
            'acquire-to-release-entry is a conservative interior hold, not full lock ownership duration',
            'attempt elapsed includes scheduling, observer and uncontended execution; not spin cycles',
            'reader set is never advertised as complete; overlapping holders are unioned, not added'],
        performance_certification='NOT_ACCEPTED')


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('record',type=Path); p.add_argument('raw',type=Path); p.add_argument('output',type=Path)
    a=p.parse_args()
    if a.raw.stat().st_size>16<<20: raise ValueError('bounded raw required')
    r=analyze(json.loads(a.record.read_text()),a.raw.read_bytes())
    with a.output.open('x') as stream: json.dump(r,stream,indent=2)
