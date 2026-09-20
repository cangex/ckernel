# SPDX-License-Identifier: GPL-2.0
"""Independent checks for Y6 private-container CPU fixture observations."""
import json
from pathlib import Path
import re
import sys
from cpu_report import analyze
from owner_report import fields
from source_switches import validate

CASES=dict(sharedCPU=[0,0],separateCPU=[0,1],quota=[0,1],migration=[0,0],background=[0,1])

def order():
    return [dict(case=case,round=r,enabled=on,label='%sR%d%s'%(case,r,'ON' if on else 'OFF'))
            for case in CASES for r in range(1,4) for on in ((False,True) if r%2 else (True,False))]

def workload(log,actor,window):
    rows=[fields(l.split(' ',1)[1]) for l in log.splitlines() if l.startswith('CPU_WORKLOAD ')]
    if len(rows)!=1: raise ValueError('one workload terminal required')
    r=rows[0]
    if (set(r)!=set('actor begin end cpu_ns ops checksum migrations'.split()) or r['actor']!=actor or
            not window['start_ns']<=r['begin']<r['end']<window['end_ns'] or
            min(r['cpu_ns'],r['ops'])<=0): raise ValueError('workload boundary or progress')
    return r

def check(state,logs,record=None,raw=None):
    errors=[]; name=state['case']; window=state['window']; report=None
    work=[workload(l,i,window) for i,l in enumerate(logs)]
    before,after=state['before'],state['after']
    validate(state['active_sources'],'cpu' if state['enabled'] else None,before['before_ns'],after['after_ns'])
    validate(state['idle_sources'],None,before['before_ns'],after['after_ns'])
    quotas=[]
    for a,b in zip(before['roots'],after['roots']):
        def stats(v): return dict((k,int(n)) for k,n in (l.split() for l in v['cpu.stat'].splitlines()))
        aa,bb=stats(a),stats(b)
        quotas.append({k:bb[k]-aa[k] for k in ('nr_throttled','throttled_usec')})
    if name=='quota' and (quotas[0]['nr_throttled']<=0 or quotas[0]['throttled_usec']<=0): errors.append('quota not exercised')
    if name!='quota' and any(v['nr_throttled'] for v in quotas): errors.append('unexpected quota')
    if state['exit_codes']!=[0,0]: errors.append('workload failure')
    if state['enabled']:
        report=analyze(record,raw)
        if report['quality']['status']!='PASS' or not report['execution']: errors.append('capture quality/execution')
        ids=[list((record['root_identities'][t][k] for k in ('id','generation'))) for t in state['targets']]
        cross=[r for r in report['associations'] if r['waiter'] in ids and r['executor'] in ids and r['waiter']!=r['executor']]
        if name=='sharedCPU' and not cross: errors.append('shared CPU association not detected')
        if name in ('separateCPU','quota','background') and cross: errors.append('false cross CPU association')
        if name=='migration' and (work[0]['migrations']<5 or
                sum(v['identity']==ids[0] for v in report['migrations'])<5):
            errors.append('migration coverage')
        if not sum(v['entries'] for v in report['interrupt_totals']): errors.append('interrupt coverage')
        if name=='background':
            truth=[fields(l.split(' ',1)[1]) for text in logs for l in text.splitlines() if l.startswith('CPU_WORK_TRUTH ')]
            matched=[r for r in report['background'] if any(r['object']==t['object'] and
                r['begin_ns']<=t['start']<=t['end']<=r['end_ns'] for t in truth)]
            if len(truth)!=80 or len(matched)<80: errors.append('background execution coverage')
            if any(r['origin'] is not None for r in matched): errors.append('worker mistaken for origin')
            if not sum(r['observed_irq_subtracted_execution_ns'] for r in matched): errors.append('background CPU slice absent')
    return dict(status='FAIL' if errors else 'PASS_SCOPED',errors=errors,workloads=work,quota_deltas=quotas,
        cpu_report_summary=None if report is None else dict(points=report['points'],
            execution=len(report['execution']),waits=len(report['runnable_offcpu']),
            associations=len(report['associations']),interrupts=sum(v['entries'] for v in report['interrupt_totals']),
            background=len(report['background']),unknown=report['unknown']))

def replay(serial,destination):
    root=Path(destination); root.mkdir(parents=True,exist_ok=False)
    text=Path(serial).read_text(); prefix='/tmp/y6-cpu-evidence/'
    if 'CIS_PROFILE_VM_EXIT=0' not in text: raise ValueError('guest failed')
    marker=re.compile(r'^CIS_FILE (.+)$',re.M)
    matches=list(marker.finditer(text)); count=0
    for i,m in enumerate(matches):
        path=m[1].strip()
        if not path.startswith(prefix): raise ValueError('unexpected artifact')
        name=path[len(prefix):]
        if not name or '..' in Path(name).parts: raise ValueError('unsafe artifact')
        end=matches[i+1].start() if i+1<len(matches) else text.index('CIS_FILES_END',m.end())
        value=text[m.end()+1:end].rstrip('\r\n')+'\n'
        p=root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(value); count+=1
    result=json.loads((root/'result.json').read_text()); states=result['states']
    if [dict((k,s[k]) for k in ('case','round','enabled','label')) for s in states]!=order(): raise ValueError('matrix/order')
    checked=[]
    for s in states:
        sid=s['session_id']; r=json.loads((root/'records'/(sid+'.json')).read_text()) if sid else None
        raw=(root/'records'/(sid+'.jsonl')).read_bytes() if sid else None
        answer=check(s,[(root/(s['label']+'-%d.log'%i)).read_text() for i in range(2)],r,raw)
        if answer!=s['result'] or answer['status']!='PASS_SCOPED': raise ValueError(answer)
        checked.append(answer)
    receipt=dict(status='PASS_SCOPED',states=len(checked),files=count,checks=checked)
    (root/'replay.json').write_text(json.dumps(receipt,indent=2)); return receipt

if __name__=='__main__': print(json.dumps(replay(*sys.argv[1:]),indent=2))
