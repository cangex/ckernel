#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Rebuild real survey candidates and verify shared-slot routing from raw artifacts."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from diagnosis_plan import recommend
from owner_report import fields
from session_check import extract
from session_quality import assess
from source_switches import validate as validate_sources
from survey import summarize
from unified_report import analyze


def check(text):
    files=extract(text); prefix='/tmp/diagnosis-evidence/'
    def value(path): return json.JSONDecoder().raw_decode(files[prefix+path].lstrip())[0]
    plan=value('plan.json'); result=value('result.json'); errors=[]
    if plan.get('schema')!='cis-x6-plan-v1' or result.get('schema')!='cis-x6-result-v1':
        raise ValueError('unsupported routing cohort')
    if (plan['interval_s']!=60 or plan['min_samples']!=32 or not plan['no_fake_clock'] or
            result['source']!=plan['source']): errors.append('plan_or_source')
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): errors.append('guest_exit')
    if value('workload-exits.json')!=[0]*4: errors.append('workload_exit')
    requests=[json.loads(r) for r in files[prefix+'requests.jsonl'].splitlines() if r.startswith('{')]
    if len(requests)>8000: raise ValueError('request audit capacity')
    for a,b in zip(requests,requests[1:]):
        if not a['before_ns']<=a['after_ns']<=b['before_ns']: errors.append('request_time')
    def ops(name,ok=True): return [r for r in requests if r['request']['op']==name and r['response']['ok'] is ok]
    records=[value('records/'+sid+'.json') for sid in result['sessions']]
    records.sort(key=lambda r:r['requested_ns']); summaries={}; relations={}; previous={}
    checks={r['name']:r for r in result['checks']}
    reference=next(r for r in records if r['session_id']==checks['real_reference']['session'])
    pressure=next(r for r in records if r['session_id']==checks['real_pressure_to_two_candidates']['session'])
    last_end=max(r['window']['end_ns'] for r in records)
    for mode,first in (('syscalls',reference),('cpu',pressure)):
        for role in range(2):
            rows=[fields(r) for r in files[prefix+'%s-%d.log'%(mode,role)].splitlines() if r.startswith('CIS_ROUTE_WORK ')]
            if (len(rows)!=1 or rows[0].get('operations',0)<=0 or
                    not rows[0]['begin_ns']<first['window']['start_ns']<last_end<rows[0]['end_ns']):
                errors.append('workload_window_coverage')
    with tempfile.TemporaryDirectory() as tmp:
        for record in records:
            sid=record['session_id']; raw=files[prefix+'records/'+sid+'.jsonl'].encode()
            if any(record.get(k)!=v for k,v in plan['source'].items()): errors.append('record_source')
            if assess(record)['status']!='PASS': errors.append('record_quality')
            report=analyze(record,raw)
            if report['quality']['status']!='PASS' or report['scope_audit'].get('status','PASS')!='PASS': errors.append('explanation_quality')
            relations[sid]=dict(collector=record['collector'],relations=len(report['relations']),timing=report['timing'])
            if record['collector']=='ip':
                path=Path(tmp)/(sid+'.jsonl'); path.write_bytes(raw)
                rebuilt=summarize(record,path,previous,plan['min_samples'])
                if rebuilt!=record['survey']: errors.append('survey_not_reproducible')
                summaries[sid]=rebuilt
                for key,row in rebuilt['roots'].items():
                    if row['valid'] and (key not in previous or previous[key]['epoch']!=row['epoch']): previous[key]=row
    for before,after in zip(records[1:],records[2:]):
        if after['requested_ns']-before['requested_ns']<60_000_000_000: errors.append('shared_interval')
    planned=[r for r in records if r.get('scheduled')]
    automatic=[r for r in planned if r['scheduled'].get('kind')=='automatic_diagnosis']
    manual=[r for r in planned if r['scheduled'].get('kind')=='manual_diagnosis']
    if len(automatic)!=2 or len(manual)!=1: errors.append('route_counts')
    for row in manual+automatic:
        item=row['scheduled']['diagnosis']; prior=summaries.get(item['source_session'])
        if prior is None: errors.append('missing_candidate_source'); continue
        source_record=next(r for r in records if r['session_id']==item['source_session'])
        rebuilt=recommend(dict(quality=dict(status='PASS'),session_id=item['source_session'],
            window=source_record['window'],survey_epoch=source_record['survey_epoch'],
            candidates=[dict(v,target=k) for k,v in prior['roots'].items()]))
        proposal=next((p for p in rebuilt if (p['target'],p['collector'])==(item['target'],item['collector'])),None)
        if not proposal or any(item.get(k)!=v for k,v in proposal.items()): errors.append('candidate_not_from_observation')
        if row['targets']!=[item['target']] or row['collector']!='sched': errors.append('route_target')
        if not 0<=item['sample_age_ns']<300_000_000_000 or item['queue_wait_ns']<0: errors.append('source_age')
        if row in automatic and not item['automatic_eligible']: errors.append('automatic_without_anomaly')
    if len(automatic)==2 and len(manual)==1:
        if len({r['targets'][0] for r in automatic})!=2 or automatic[0]['targets']==manual[0]['targets']:
            errors.append('target_fairness')
    last=None
    for row in records:
        if row in automatic and last!='ip': errors.append('ordinary_interleave')
        last=row['collector']
    rejected=ops('diagnosis_run',False)
    if len(rejected)!=1 or 'host interval' not in rejected[0]['response'].get('error',''): errors.append('shared_interval_refusal')
    last_queue=ops('diagnosis_status')[-1]['response']['data']
    if last_queue['auto_started']!=2 or last_queue['enabled'] or last_queue['items']: errors.append('restart_budget')
    if not ops('survey_epoch') or not ops('schedule_pause'): errors.append('cleanup_operations')
    validate_sources(result['idle_sources'],None,max(r['window']['end_ns'] for r in records),2**64-1)
    return dict(schema='cis-x6-check-v1',status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),
        records=len(records),automatic=len(automatic),manual=len(manual),reports=relations,
        serial_sha256=hashlib.sha256(text.encode()).hexdigest(),source=plan['source'],
        performance_certification='NOT_ACCEPTED',periodic_wait='schedule-specific, not explanation lag')


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path); a=p.parse_args()
    if a.serial.stat().st_size>128<<20: raise ValueError('serial input capacity')
    result=check(a.serial.read_text())
    with a.output.open('x') as f: json.dump(result,f,indent=2)
    print(json.dumps({k:result[k] for k in ('status','errors','records','automatic','manual')}))
    raise SystemExit(result['status']!='PASS')
