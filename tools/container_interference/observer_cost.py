#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Predeclared R1 component costs. System deltas are not exclusive ownership."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import statistics
from overhead import interval
from resource_report import analyze as resource_report
from cost_snapshots import parse as cost_snapshots

FIELDS=re.compile(r'(\w+)=([^ ;]+)')
PROFILES=('off-a','off-b','metrics','psi','ip','full')
BAD={'capture_failure','budget_disable','capture_error','sample_schema_error',
     'metrics_budget_disable','budget_unavailable','entry_budget_disable','buffer_loss','fast_source_error'}


def analyze(text):
    sections,section={},'boot'
    for line in text.splitlines():
        if line.startswith('CIS_FILE '):
            section=line.split(' ',1)[1]
        else:
            sections.setdefault(section,[]).append(line)
    trials,failures={},[]
    for name,lines in sections.items():
        m=re.fullmatch(r'/tmp/r1-(bench|open-loop)-(\d+)-(off-a|off-b|metrics|psi|ip|full)\.log',name)
        if not m: continue
        work,rnd,profile=m[1],int(m[2]),m[3]
        starts=[dict(FIELDS.findall(x)) for x in lines if x.startswith('CIS_FLEET_BEGIN ')]
        if len(starts)!=1 or 'CIS_FLEET_END result=PASS' not in lines:
            failures.append({'case':name,'reason':'run failed or no unique window'});continue
        f=starts[0]; begin=int(f['start_ns']);finish=begin+int(f['duration'])*10**9
        trial={'window':[begin,finish],'values':{},'observer_events':collections.Counter(),'samples':collections.Counter(),'budgets':[],'inventory':[]}
        trial['system_snapshots']=cost_snapshots(lines)
        for error in trial['system_snapshots']['quality_errors']:
            failures.append({'case':name,'reason':error})
        if int(f['count'])!=2 or int(f['duration'])!=15 or int(f['target'])!=rnd%2:
            failures.append({'case':name,'reason':'frozen layout mismatch'})
        for line in lines:
            if not line.startswith(('CIS_RESULT ','CIS_LATENCY ')):continue
            v=dict(FIELDS.findall(line));slot=int(v['cgroup'].rsplit('-',1)[1])
            if slot in trial['values'] or int(v.get('errors',0)) or int(v.get('timeouts',0)):
                failures.append({'case':name,'reason':'duplicate or failed operation'})
            trial['values'][slot]=(int(v['operations'])*10**9/(int(v['end_ns'])-int(v['start_ns'])) if work=='bench' else int(v['p99_ns']))
        if set(trial['values'])!={0,1}: failures.append({'case':name,'reason':'missing container'})
        roots=set()
        for line in sections.get('/tmp/observer-'+f['observer_pid']+'.jsonl',[]):
            # The VM console also contains QMP JSON; it is not a CIS record.
            if not line.startswith('{"version":'):continue
            try:e=json.loads(line)
            except ValueError:failures.append({'case':name,'reason':'invalid JSON'});continue
            k=e['kind'];d=dict(FIELDS.findall(e.get('detail','')))
            trial['observer_events'][k]+=1
            if k in BAD or k=='final_quality' and any(int(d.get(x,0)) for x in ('errors','drops')):
                failures.append({'case':name,'event':e})
            if k=='register':roots.add(e['id'])
            if k=='IP' and begin<=int(d['sample_time_ns'])<finish:trial['samples'][e['id']]+=1
            if k=='budget':trial['budgets'].append(d)
            if k=='kernel_memory_inventory':trial['inventory'].append(d)
        if profile not in ('off-a','off-b') and len(roots)!=2:
            failures.append({'case':name,'reason':'registration coverage'})
        if profile in ('ip','full') and any(not trial['samples'][r] for r in roots):
            failures.append({'case':name,'reason':'no IP for an active container'})
        trials[(work,rnd,profile)]=trial
    expected={(w,r,p) for w in ('bench','open-loop') for r in range(1,6) for p in PROFILES}
    if set(trials)!=expected: failures.append({'reason':'matrix mismatch','missing':sorted(expected-set(trials)),'unexpected':sorted(set(trials)-expected)})
    results=[]
    for work in ('bench','open-loop'):
        for profile in PROFILES[1:]:
            for role in ('target','bystander'):
                pairs,absolute=[],[]
                for rnd in range(1,6):
                    slot=(rnd+(role=='bystander'))%2
                    a=trials.get((work,rnd,'off-a'),{}).get('values',{}).get(slot)
                    b=trials.get((work,rnd,profile),{}).get('values',{}).get(slot)
                    if a and b:
                        pairs.append(100*(1-b/a) if work=='bench' else 100*(b/a-1));absolute.append(b-a)
                ci=interval(pairs) if pairs else [None,None];threshold=1 if work=='bench' else 2
                status='BLOCKED' if len(pairs)!=5 or ci[1] is None else 'PASS' if ci[1]<=threshold else 'FAIL' if ci[0]>threshold else 'UNRESOLVED'
                results.append({'profile':profile,'workload':work,'role':role,'n':len(pairs),'mean_percent':statistics.mean(pairs) if pairs else None,
                                '95pct_interval':ci,'threshold_percent':threshold,'status':status,'paired_percent':pairs,
                                'mean_absolute_change':statistics.mean(absolute) if absolute else None})
    return {'version':1,'raw_sha256':hashlib.sha256(text.encode()).hexdigest(),'trials':[dict(case=k,**v) for k,v in trials.items()],
            'results':results,'failures':failures,'run_count':len(trials),'resources':resource_report(text),
            'screen_numeric_pass':not failures and all(x['status']=='PASS' for x in results if x['profile']=='full'),
            'scope':'R1 component decomposition; 2 containers ARM64 KVM; no owner/dentry performance acceptance',
            'memory_complete':False,'background_owner_complete':False,
            'notes':['off-b versus off-a measures test variability, not CIS cost.',
                     'RSS, mapped buffers, fdinfo and cgroup charges overlap; do not sum.',
                     'CPU deltas include changed business work and unknown background; not exclusive observer ownership.',
                     'No full-profile S6 release can be inferred from this screen alone.']}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('log',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();r=analyze(a.log.read_text())
    with a.output.open('x') as f:json.dump(r,f,indent=2);f.write('\n')
    print(json.dumps({'runs':r['run_count'],'failures':len(r['failures']),'full': [x for x in r['results'] if x['profile']=='full']},indent=2))
