# SPDX-License-Identifier: GPL-2.0
"""Bounded CPU execution associations; never an inferred causal blocker."""
from bisect import bisect_left
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from collector_audit import audit
from explain import explain, within_window
from owner_report import fields

MAX_POINTS=16384
MAX_ASSOCIATIONS=4096
KEYS=set(('protocol time_ns cpu phase tid task_start actor_id actor_generation next_tid '
          'next_start next_id next_generation value flags destination object function').split())


def union(intervals):
    result=[]
    for a,b in sorted(intervals):
        if b<=a: continue
        if result and a<=result[-1][1]: result[-1][1]=max(b,result[-1][1])
        else: result.append([a,b])
    return result


def overlap(a,b,intervals):
    return sum(max(0,min(b,y)-max(a,x)) for x,y in intervals)


def timeline(points,cpus):
    """Input already schema/identity/window checked; boundary partials explicit."""
    running={}; pending={}; irq=defaultdict(list); works={}
    runs=[]; waits=[]; interrupts=[]; background=[]; native_wait=[]
    unknown=Counter(); defects=Counter(); seen=set()
    for d in sorted(points,key=lambda d:(d['time_ns'],d['cpu'])):
        t=d['time_ns']; cpu=d['cpu']; phase=d['phase']
        key=(d['tid'],d['task_start']); ident=(d['actor_id'],d['actor_generation'])
        duplicate=tuple(d[k] for k in sorted(KEYS))
        if duplicate in seen: defects['duplicate_point']+=1; continue
        seen.add(duplicate)
        if phase==2:
            if pending.pop(key,None): unknown['migrated_wait']+=1
            continue
        if cpu not in cpus: defects['unselected_cpu']+=1; continue
        if phase==1:
            previous=running.pop(cpu,None)
            if previous:
                if previous['task']!=key: defects['switch_sequence_gap']+=1
                elif previous['identity']!=ident: unknown['execution_identity_changed']+=1
                else:
                    runs.append(dict(cpu=cpu,task=list(key),identity=list(ident),begin_ns=previous['time'],end_ns=t))
            else: unknown['execution_left_boundary']+=1
            next_key=(d['next_tid'],d['next_start']); next_id=(d['next_id'],d['next_generation'])
            p=pending.pop(next_key,None)
            if p:
                if p['cpu']==cpu and p['identity']==next_id:
                    waits.append(dict(cpu=cpu,task=list(next_key),identity=list(next_id),begin_ns=p['time'],end_ns=t))
                else: unknown['wait_cpu_or_identity_changed']+=1
            if key[0] and ident!=(0,0) and (d['flags'] or d['value']==0):
                if key in pending: defects['duplicate_runnable_out']+=1
                pending[key]=dict(cpu=cpu,time=t,identity=ident)
            running[cpu]=dict(task=next_key,identity=next_id,time=t)
        elif phase==3:
            if ident!=(0,0): native_wait.append(dict(cpu=cpu,task=list(key),identity=list(ident),
                end_ns=t,reported_wait_ns=d['value'],additive=False))
        elif phase in (4,6):
            if len(irq[cpu])>=8: defects['irq_nesting_capacity']+=1
            else: irq[cpu].append((phase,d['value'],t))
        elif phase in (5,7):
            if not irq[cpu]: unknown['irq_left_boundary']+=1
            elif irq[cpu][-1][:2]!=(phase-1,d['value']):
                defects['irq_pair_mismatch']+=1; irq[cpu].clear()
            else:
                p,vector,begin=irq[cpu].pop()
                interrupts.append(dict(cpu=cpu,kind='irq_handler' if p==4 else 'softirq',
                    vector=vector,begin_ns=begin,end_ns=t,owner=None))
        elif phase==8:
            if key in works: unknown['nested_work']+=1; works[key]=None
            else: works[key]=dict(cpu=cpu,object=d['object'],function=d['function'],begin_ns=t,
                                 task=list(key),executor=list(ident),origin=None)
        elif phase==9:
            w=works.pop(key,None)
            if not w: unknown['work_left_boundary_or_nested']+=1
            elif w['object']!=d['object'] or w['function']!=d['function']:
                defects['work_pair_mismatch']+=1
            else:
                w.update(end_ns=t,end_cpu=cpu); background.append(w)
    unknown['execution_right_boundary']=len(running)
    unknown['wait_right_boundary']=len(pending)
    unknown['irq_right_boundary']=sum(len(v) for v in irq.values())
    unknown['work_right_boundary']=len(works)
    irq_union={cpu:union((r['begin_ns'],r['end_ns']) for r in interrupts if r['cpu']==cpu) for cpu in cpus}
    by_cpu=defaultdict(list); by_task=defaultdict(list)
    for r in runs:
        r['observed_interrupt_ns']=overlap(r['begin_ns'],r['end_ns'],irq_union[r['cpu']])
        r['irq_subtracted_slice_ns']=r['end_ns']-r['begin_ns']-r['observed_interrupt_ns']
        by_cpu[r['cpu']].append(r); by_task[tuple(r['task'])].append(r)
    ends={cpu:[r['end_ns'] for r in values] for cpu,values in by_cpu.items()}
    associations=[]
    for w in waits:
        a,b=w['begin_ns'],w['end_ns']; cpu=w['cpu']
        w['observed_interrupt_ns']=overlap(a,b,irq_union[cpu]); w['blocking_container']=None
        values=by_cpu[cpu]
        for i in range(bisect_left(ends.get(cpu,[]),a),len(values)):
            r=values[i]
            if r['begin_ns']>=b: break
            x,y=max(a,r['begin_ns']),min(b,r['end_ns'])
            if x>=y or r['task']==w['task'] or r['identity'] in ([0,0],w['identity']): continue
            if len(associations)>=MAX_ASSOCIATIONS: defects['association_capacity']+=1; break
            associations.append(dict(cpu=cpu,waiter=w['identity'],executor=r['identity'],
                begin_ns=x,end_ns=y,observed_interrupt_ns=overlap(x,y,irq_union[cpu]),
                relation='execution_during_runnable_offcpu_interval',evidence='E1',blocking_container=None))
    for w in background:
        slices=[]
        for r in by_task.get(tuple(w['task']),[]):
            a,b=max(w['begin_ns'],r['begin_ns']),min(w['end_ns'],r['end_ns'])
            if a<b: slices.append(dict(cpu=r['cpu'],begin_ns=a,end_ns=b,
                irq_subtracted_slice_ns=b-a-overlap(a,b,irq_union[r['cpu']])))
        w['observed_slices']=slices
        w['observed_irq_subtracted_execution_ns']=sum(s['irq_subtracted_slice_ns'] for s in slices)
        w['wall_ns']=w['end_ns']-w['begin_ns']
        w['complete_cpu_cost']=False
    if defects: associations=[]
    return dict(execution=runs,runnable_offcpu=waits,interrupts=interrupts,background=background,
        native_sched_wait=native_wait,associations=associations,unknown=dict(unknown),defects=dict(defects))


def analyze(record,raw):
    if record.get('collector')!='cpu' or len(raw)>16<<20: raise ValueError('bounded CPU capture required')
    cpus=record.get('cpu_selection')
    if (not isinstance(cpus,list) or not 1<=len(cpus)<=8 or any(type(c) is not int or not 0<=c<512 for c in cpus)
            or len(set(cpus))!=len(cpus)): raise ValueError('CPU selection required')
    base=explain(record,raw); scope=audit(record,raw); rows=[]; selected=[]; excluded=Counter()
    identities=dict(record.get('root_identities',{})); identities.update(record.get('owner_identities',{}))
    known={(r['id'],r['generation']) for r in identities.values()}
    for line in raw.splitlines():
        r=json.loads(line)
        if r.get('kind')=='cpu_selection': selected.append(fields(r.get('detail','')))
        if r.get('kind')!='CPU_POINT': continue
        d=fields(r.get('detail',''))
        if (set(d)!=KEYS or any(type(v) is not int or v<0 for v in d.values()) or d['protocol']!=1 or
                not 1<=d['phase']<=9 or d['cpu']>=512 or d['destination']>=512 or d['flags'] not in (0,1) or
                not within_window(record,d['time_ns'],d['time_ns']) or d['time_ns']>=record['window']['end_ns']):
            excluded['schema_window']+=1; continue
        for prefix in ('actor','next'):
            pair=(d[prefix+'_id'],d[prefix+'_generation'])
            if pair!=(0,0) and pair not in known: excluded['identity']+=1
        if (d['phase'] in (4,5,6,7) and any(d[k] for k in ('tid','task_start','actor_id','actor_generation')) or
                d['phase'] in (8,9) and not (d['tid'] and d['task_start'] and d['object'] and d['function'])):
            excluded['context']+=1; continue
        if len(rows)>=MAX_POINTS: excluded['point_capacity']+=1; continue
        rows.append(d)
    expected=[dict(cpu=c,count=len(cpus),readback=1) for c in cpus]
    if selected!=expected: excluded['selection_readback']+=1
    result=timeline(rows,set(cpus)); quality=base['quality']
    if excluded or result['defects'] or scope['status']!='PASS':
        quality=dict(quality,status='FAIL',defects=quality['defects']+['cpu_audit'])
    if quality['status']!='PASS': result['associations']=[]
    return dict(schema='cis-cpu-background-report-v1',quality=quality,scope_audit=scope,
        source=base['source'],raw_sha256=hashlib.sha256(raw).hexdigest(),cpu_selection=cpus,
        analysis_source_sha256=dict(base['analysis_source_sha256'],
            cpu_report=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()),
        points=len(rows),excluded=dict(excluded),**result,
        limits=['same-CPU execution association is not a unique blocker or causal proof',
                'only runnable switch-out waits fully contained on one CPU are joined; wakeup and migration waits are not reconstructed',
                'quota is a separate cgroup boundary counter, not attributed to another container',
                'IRQ handler/softirq unions observed; NMI, entry/exit overhead and vCPU steal remain unmeasured',
                'work executor and function identified; submitter and merged/requeued ownership unknown',
                'work address is one execution token, never a persistent owner key',
                'observed execution slices exclude recorded interrupts only, not an exact total backend CPU cost',
                'native sched_stat_wait and switch-out brackets overlap and must not be added'])
