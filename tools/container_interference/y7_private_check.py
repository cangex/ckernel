# SPDX-License-Identifier: GPL-2.0
"""Frozen Y7 private-storage cohort, not a complete Y7 acceptance receipt."""
import json
from pathlib import Path
import sys
from joint_costs import analyze as costs
from joint_vm_check import cpu_snapshot
from owner_report import fields
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate
from unified_report import analyze

MODES=('off','survey','profile')
COLLECTORS=('ip','counter','page_backend','filesystem','block','cpu')
ROLES=((0,2),(1,3),(0,3))

def order():
    return [dict(round=r,mode=m,label='%sR%d'%(m,r)) for r in range(3)
            for m in (MODES if r%2==0 else tuple(reversed(MODES)))]

def captures(mode):
    return () if mode=='off' else ('ip',) if mode=='survey' else COLLECTORS

def workload(text):
    rows=[fields(l.split(' ',1)[1]) for l in text.splitlines() if l.startswith('Y7_PRIVATE ')]
    samples=[l.split(' ',1)[1] for l in text.splitlines() if l.startswith('Y7_LATENCIES ')]
    if len(rows)!=1 or len(samples)!=1: raise ValueError('one complete workload record required')
    r=rows[0]; v=[int(n) for n in samples[0].split(',')]
    if (set(r)!=set('actor dev inode due begin end offered completed errors timeouts period timeout p99 max sum'.split()) or
            not 0<=r['actor']<4 or r['errors'] or r['offered']!=6000 or r['completed']!=6000 or
            r['period']!=3_000_000 or r['timeout']!=100_000_000 or len(v)!=6000 or v!=sorted(v) or min(v)<0 or
            r['p99']!=v[5939] or r['max']!=v[-1] or r['sum']!=sum(v) or
            r['timeouts']!=sum(n>r['timeout'] for n in v) or not r['due']<=r['begin']<r['end']):
        raise ValueError('arrival-relative timing or business integrity')
    return dict(r,throughput=6000e9/(r['end']-r['due']))

def cost_fields(state,plan):
    c=costs(state['before'],state['after'],plan['clock_ticks'])
    a=cpu_snapshot(state['before']['proc_stat']);b=cpu_snapshot(state['after']['proc_stat'])
    if a.keys()!=b.keys(): raise ValueError('CPU topology changed')
    cpu={k:[q-p for p,q in zip(a[k],b[k])] for k in a}
    if any(v<0 for row in cpu.values() for i,v in enumerate(row) if i!=4): raise ValueError('cpu_accounting_regression')
    return dict(system_cost=c,cpu_delta_ticks=cpu)

def check(state,logs,records,raws,plan):
    errors=[]; work=[workload(t) for t in logs]; observations=[]
    selected=[state['all_targets'][i] for i in ROLES[state['round']]]
    if state['targets']!=selected or state['exit_codes']!=[0]*4: errors.append('roles_or_exit')
    objects=[]
    for i,w in enumerate(work):
        if w['actor']!=i or w['due']!=state['start_ns']: errors.append('business_binding')
        expected=plan['directories'][i]
        if (w['dev'],w['inode'])!=(expected['dev'],expected['inode']): errors.append('private_directory_binding')
        objects.append((w['dev'],w['inode']))
    if len(set(objects))!=4: errors.append('directories_not_private')
    expected=captures(state['mode'])
    if len(records)!=len(expected) or len(raws)!=len(expected) or len(state['sessions'])!=len(expected):
        raise ValueError('capture population')
    for i,(collector,record,raw) in enumerate(zip(expected,records,raws)):
        observation=state['sessions'][i]
        if (record['collector']!=collector or record['targets']!=selected or
                str(record['session_id'])!=str(observation['session_id']) or
                any(record.get(k)!=plan['source'][k] for k in SOURCE_KEYS)):
            errors.append('source_or_capture_binding')
        window=record['window']
        if not max(v['begin'] for v in work)<window['start_ns']<window['end_ns']<min(v['end'] for v in work):
            errors.append('business_window_coverage')
        report=analyze(record,raw)
        if report['quality']['status']!='PASS' or not record.get('objects_absent'): errors.append('quality_or_cleanup')
        validate(observation['active_sources'],collector,record['receipt']['prepared_ns'],window['end_ns'])
        validate(observation['idle_sources'],None,window['end_ns'],2**64-1)
        if any(r['causal']!='NOT_ESTABLISHED' for r in report['relations']): errors.append('causal_overclaim')
        observations.append(dict(collector=collector,quality=report['quality'],relations=report['relations'],
            omitted=report.get('omitted_relations'),process_cpu=record.get('process_cpu_budget'),
            rss_bytes=record.get('combined_rss_peak_bytes'),report=report))
    validate(state['idle_sources'],None,0,2**64-1)
    measured=cost_fields(state,plan)
    for actor in measured['system_cost']['actors']:
        if actor['memory_events_delta'].get('oom',0) or actor['memory_events_delta'].get('oom_kill',0): errors.append('business_oom')
    return dict(status='FAIL' if errors else 'PASS_SCOPED',errors=sorted(set(errors)),workloads=work,
                **measured,observations=observations)

def replay(serial,destination):
    text=Path(serial).read_text();files=extract(text);prefix='/tmp/y7-private-evidence/'
    def value(n): return json.JSONDecoder().raw_decode(files[prefix+n].lstrip())[0]
    plan=value('plan.json');declared=value('result.json');permit=value('permit.json')
    if (plan['schema']!='cis-y7-private-plan-v1' or plan['order']!=order() or
            plan['arrangement'] not in ('shared','separate') or len(declared['states'])!=9 or
            any(plan['source'][k]!=permit['source'][k] for k in SOURCE_KEYS)):
        raise ValueError('matrix or source binding')
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): raise ValueError('guest failed')
    if any(s in text for s in ('Oops:','Kernel panic','BUG: KASAN:','WARNING: CPU:')): raise ValueError('kernel failure')
    out=Path(destination);out.mkdir(mode=0o700);states=[]
    for entry in order():
        label=entry['label'];s=value(label+'-evidence.json')
        if any(s[k]!=entry[k] for k in entry): raise ValueError('state binding')
        records=[value('records/'+v['session_id']+'.json') for v in s['sessions']]
        raws=[(files[prefix+'records/'+v['session_id']+'.jsonl'].rstrip()+'\n').encode() for v in s['sessions']]
        checked=check(s,[files[prefix+label+'-%d.log'%i] for i in range(4)],records,raws,plan)
        (out/(label+'-check.json')).write_text(json.dumps(checked,indent=2))
        if checked['status']!='PASS_SCOPED': raise ValueError(checked['errors'])
        states.append(dict(**entry,**checked))
    comparisons=[]
    for r in range(3):
        off=next(s for s in states if s['round']==r and s['mode']=='off')
        for s in (s for s in states if s['round']==r and s['mode']!='off'):
            for i,(a,b) in enumerate(zip(off['workloads'],s['workloads'])):
                comparisons.append(dict(round=r,mode=s['mode'],actor=i,role='target' if i in ROLES[r] else 'bystander',
                    p99_delta_ns=b['p99']-a['p99'],p99_change=b['p99']/a['p99']-1 if a['p99'] else None,
                    throughput_change=b['throughput']/a['throughput']-1,timeouts_before=a['timeouts'],timeouts_after=b['timeouts']))
    receipt=dict(status='PASS_SCOPED',y7_complete=False,cohort='private_storage',arrangement=plan['arrangement'],
        states=states,comparisons=comparisons,source=plan['source'],
        limits=['fixed offered rate, not saturated throughput','P99 record-only',
                'VM scope, no bare-metal or population guarantee','whole-VM and management costs are not observer-exclusive',
                'network joint cohort and final Y7 coverage reconciliation remain required'])
    (out/'verification.json').write_text(json.dumps(receipt,indent=2))
    return dict(status=receipt['status'],states=len(states),captures=sum(len(s['observations']) for s in states))

if __name__=='__main__': print(json.dumps(replay(*sys.argv[1:])))
