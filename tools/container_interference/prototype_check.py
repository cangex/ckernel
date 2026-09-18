#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Extract and verify a task-owned prototype VM serial transcript."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics

from session_check import extract, numbers
from explain import explain, markdown
from explanation_check import check_owner


def exploratory_cost(files, declared):
    data={};rows=[]
    for item in declared.get('measurements',[]):
        for role in range(2):
            prefix='CIS_RESULT ' if item['workload']=='throughput' else 'CIS_LATENCY '
            lines=files.get('/tmp/prototype-evidence/%s-%d.log'%(item['label'],role),'').splitlines()
            values=[numbers(line) for line in lines if line.startswith(prefix)]
            if len(values)!=1:raise ValueError('missing/duplicate cost result; no dropped pairs')
            if values[0].get('end_ns',0)<=values[0].get('start_ns',0):
                raise ValueError('invalid cost window')
            if values[0].get('operations' if item['workload']=='throughput' else 'p99_ns',0)<=0:
                raise ValueError('invalid cost denominator')
            data[(item['workload'],item['repetition'],item['mode'],role)]=values[0]
    for workload in declared.get('plan',{}).get('workloads',[]):
        for mode in ('ip','owner','sched','reclaim'):
            for role_name in ('target','observer'):
                differences=[];raw=[]
                for repetition in range(3):
                    role=repetition%2 if role_name=='target' else 1-repetition%2
                    off=data.get((workload,repetition,'off',role))
                    trial=data.get((workload,repetition,mode,role))
                    if not off or not trial:continue
                    if workload=='throughput':
                        a=off['operations']*1e9/(off['end_ns']-off['start_ns'])
                        b=trial['operations']*1e9/(trial['end_ns']-trial['start_ns'])
                        delta=(1-b/a)*100
                    else:
                        a,b=off['p99_ns'],trial['p99_ns'];delta=(b/a-1)*100
                    differences.append(delta)
                    raw.append(dict(repetition=repetition,role=role,off=a,trial=b,
                                    off_timeouts=off.get('timeouts'),trial_timeouts=trial.get('timeouts')))
                row=dict(workload=workload,mode=mode,role=role_name,n=len(differences),raw=raw,
                         paired_pct=differences,status='RECORD_ONLY',certified=False)
                if len(differences)==3:
                    mean=statistics.mean(differences)
                    half=4.30265273*statistics.stdev(differences)/3**.5
                    row.update(mean_pct=mean,lower95_pct=mean-half,upper95_pct=mean+half)
                else:row['status']='INCOMPLETE'
                rows.append(row)
    return rows


def analyze(log, output):
    if log.stat().st_size > 128*1024*1024:
        raise ValueError('transcript exceeds VM bound')
    raw=log.read_bytes()
    files=extract(raw.decode(errors='strict'))
    output.mkdir(mode=0o700)
    result=dict(schema='cis-prototype-check-v1',transcript_sha256=hashlib.sha256(raw).hexdigest(),
                performance_certification='NOT_ACCEPTED',sessions=[],truth=[],
                analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    for name,body in files.items():
        if not name.startswith('/tmp/prototype-evidence/records/') or not name.endswith('.json'):
            continue
        record=json.JSONDecoder().raw_decode(body.lstrip())[0]
        if 'session_id' not in record:
            continue
        sid=str(record['session_id'])
        if not sid.isascii() or not sid.isdigit() or not 1<=len(sid)<=20 or Path(name).name!=sid+'.json':
            raise ValueError('invalid or aliased session artifact name')
        event_body=files.get(name[:-5]+'.jsonl','')
        event_raw=(event_body.rstrip()+'\n').encode() if event_body.strip() else b''
        report=explain(record,event_raw)
        path=output/sid
        path.with_suffix('.record.json').write_text(json.dumps(record,indent=2))
        path.with_suffix('.jsonl').write_bytes(event_raw)
        path.with_suffix('.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
        path.with_suffix('.md').write_text(markdown(report))
        elapsed=(record.get('finalized_ns',0)-(record.get('window') or {}).get('end_ns',0))/1e6
        row=dict(session_id=sid,nonce=record.get('nonce'),collector=record['collector'],
                 quality=report['quality']['status'],findings=report['finding_count'],
                 unknown=report['unknown_count'],resources=report['resources'],
                 survey_samples={key:dict(samples=value.get('samples'),status=value.get('status'))
                                 for key,value in record.get('survey',{}).get('roots',{}).items()})
        if record.get('finalized_ns'):row['finalization_lag_ms']=elapsed
        result['sessions'].append(row)
        if record['collector']=='owner':
            nonce=record['nonce']
            logs=[files.get('/tmp/prototype-evidence/%s-%d.log'%(nonce,i),'') for i in range(2)]
            if any('CIS_TRUTH ' in text for text in logs):
                check=check_owner([json.loads(line) for line in event_raw.splitlines()],logs)
                result['truth'].append(dict(nonce=nonce,**check))
    declared=files.get('/tmp/prototype-evidence/result.json')
    result['declared_result']=json.JSONDecoder().raw_decode(declared.lstrip())[0] if declared else None
    if result['declared_result'] and 'measurements' in result['declared_result']:
        result['exploratory_cost']=exploratory_cost(files,result['declared_result'])
    result['status']=('PASS' if result['declared_result'] and
                      result['declared_result'].get('prototype_functional_status')=='PASS' and
                      b'CIS_PROFILE_VM_EXIT=0' in raw and result['sessions'] and
                      all(r['quality']=='PASS' for r in result['sessions']) and
                      all(r['status']=='PASS' for r in result['truth']) else 'FAIL')
    (output/'check.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    report=analyze(args.log,args.output)
    print(json.dumps(dict(status=report['status'],sessions=len(report['sessions']),truth=report['truth']),indent=2))
    raise SystemExit(report['status']!='PASS')
