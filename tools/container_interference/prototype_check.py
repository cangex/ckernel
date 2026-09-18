#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Extract and verify a task-owned prototype VM serial transcript."""
import argparse
import hashlib
import json
from pathlib import Path

from session_check import extract
from explain import explain, markdown
from explanation_check import check_owner


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
            check=check_owner([json.loads(line) for line in event_raw.splitlines()],logs)
            result['truth'].append(dict(nonce=nonce,**check))
    declared=files.get('/tmp/prototype-evidence/result.json')
    result['declared_result']=json.JSONDecoder().raw_decode(declared.lstrip())[0] if declared else None
    result['status']=('PASS' if result['declared_result'] and result['sessions'] and
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
