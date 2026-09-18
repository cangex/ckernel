#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independently verify raw X1 discovery captures and all frozen fixture cases."""
import argparse
import hashlib
import json
from pathlib import Path

from collector_manifest import validate_inventory
from prototype_admission import SOURCE_KEYS
from session_check import extract
from sync_report import analyze
from sync_check import check

CASES=('spinShared','spinPrivate','rwMixed','rwPrivate','readersOnly','tryWrite')


def verify(serial, output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes();text=raw.decode();files=extract(text)
    prefix='/tmp/sync-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    declared,plan,permit=value('result.json'),value('plan.json'),value('permit.json')
    output.mkdir(mode=0o700)
    errors=[];cases=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): errors.append('guest_exit')
    if plan.get('cases')!=list(CASES) or plan.get('repetitions')!=3: errors.append('frozen_plan')
    expected={case+str(i) for i in range(3) for case in CASES}
    reported=declared.get('cases',[])
    if {row.get('label') for row in reported}!=expected or len(reported)!=len(expected): errors.append('missing_cases')
    if any(permit['source'].get(k)!=declared['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    rows=[]
    for path,body in files.items():
        if not path.startswith(prefix+'records/') or not path.endswith('.json'): continue
        row=json.JSONDecoder().raw_decode(body.lstrip())[0]
        if 'session_id' in row: rows.append(row)
    if len(rows)!=len(expected) or {row['nonce'] for row in rows}!=expected: errors.append('capture_set')
    for row in rows:
        label=row['nonce'];sid=str(row['session_id'])
        if label not in expected or not sid.isascii() or not sid.isdigit(): raise ValueError('unexpected case identity')
        if any(row.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source_'+label)
        validate_inventory('sync',row.get('inventory'))
        body=files[prefix+'records/'+sid+'.jsonl'];capture=(body.rstrip()+'\n').encode()
        report=analyze(row,capture)
        name=label[:-1];private=name.endswith('Private');count=2 if private else 4
        logs=[files[prefix+label+'-%d.log'%i] for i in range(count)]
        truth=check(report,logs,name in ('spinShared','rwMixed'))
        operations=[json.loads(line.split(' ',1)[1]) for log in logs for line in log.splitlines() if line.startswith('CIS_SYNC_TRUTH ')]
        if len(operations)!=16*count: errors.append('incomplete_workload_'+label)
        if private or name=='readersOnly':
            if truth['matched_intervals']: errors.append('unexpected_private_or_reader_wait_'+label)
        try_failures=sum(op['operation']==2 and op['result']==-16 for op in operations)
        if name=='tryWrite' and not try_failures: errors.append('try_failure_not_exercised_'+label)
        if any(op['result'] not in (0,-16) for op in operations): errors.append('workload_error_'+label)
        if truth['status']!='PASS': errors.append('truth_'+label)
        if report['scope_audit']['status']!='PASS': errors.append('scope_audit_'+label)
        cases.append(dict(label=label,session_id=sid,truth=truth['status'],matched=truth['matched_intervals'],
                          try_failures=try_failures,scope_audit=report['scope_audit']['status']))
        (output/(sid+'.record.json')).write_text(json.dumps(row,indent=2))
        (output/(sid+'.jsonl')).write_bytes(capture)
        (output/(sid+'.report.json')).write_text(json.dumps(report,indent=2))
        (output/(sid+'.truth.json')).write_text(json.dumps(truth,indent=2))
    for family in (1,2):
        for i in range(4):
            off=files.get(prefix+'off%d-%d.log'%(family,i),'')
            ops=[json.loads(line.split(' ',1)[1]) for line in off.splitlines() if line.startswith('CIS_SYNC_TRUTH ')]
            if len(ops)!=16 or any(op['result'] for op in ops): errors.append('off_smoke')
    result=dict(schema='cis-sync-vm-check-v1',status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),cases=cases,
                source=declared['source'],serial_sha256=hashlib.sha256(raw).hexdigest(),
                analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                scope='X1 first-layer E1 object/actor/interval discovery only',
                owner_closure='NOT_IMPLEMENTED',fd_lock_adapter='NOT_IMPLEMENTED',
                reader_set='NOT_IMPLEMENTED',x1_stage='INCOMPLETE',performance_certification='NOT_ACCEPTED')
    (output/'verification.json').write_text(json.dumps(result,indent=2))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('serial',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();result=verify(args.serial,args.output)
    print(json.dumps(result,indent=2))
    raise SystemExit(result['status']!='PASS')
