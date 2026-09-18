#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Recompute the fixed FD bridge cohort from raw serial and source-bound captures."""
import argparse
import hashlib
import json
from pathlib import Path

from session_check import extract
from prototype_admission import SOURCE_KEYS
from collector_manifest import validate_inventory
from collector_audit import audit
from explain import explain
from fd_check import check


def verify(serial, output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes();text=raw.decode();files=extract(text);prefix='/tmp/fd-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    declared,plan,permit=[value(name+'.json') for name in ('result','plan','permit')]
    output.mkdir(mode=0o700);errors=[];cases=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): errors.append('guest_exit')
    lifecycle=plan.get('suite')=='lifecycle'
    allowed=['cross','reuse'] if lifecycle else ['threads','private','native']
    if plan.get('cases')!=allowed or plan.get('repetitions')!=3: errors.append('frozen_plan')
    if lifecycle and plan.get('reuse_generations')!=4: errors.append('frozen_reuse_count')
    expected={case+str(i) for i in range(3) for case in allowed}
    if {row.get('label') for row in declared['cases']}!=expected or len(declared['cases'])!=len(expected): errors.append('declared_cases')
    if any(permit['source'].get(k)!=declared['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    rows=[]
    for path,body in files.items():
        if path.startswith(prefix+'records/') and path.endswith('.json'):
            row=json.JSONDecoder().raw_decode(body.lstrip())[0]
            if 'session_id' in row: rows.append(row)
    if len(rows)!=len(expected) or {row['nonce'] for row in rows}!=expected: errors.append('capture_set')
    for row in rows:
        label=row['nonce'];sid=str(row['session_id'])
        if label not in expected or not sid.isascii() or not sid.isdigit(): raise ValueError('case identity')
        if any(row.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source_'+label)
        validate_inventory('owner',row['inventory'])
        capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
        report=explain(row,capture);scope=audit(row,capture)
        kind=label[:-1]
        names=([label+'g%d-%d.log'%(g,i) for g in range(4) for i in range(2)] if kind=='reuse'
               else [label+'-%d.log'%i for i in range(2)])
        truth=check(report,[files[prefix+name] for name in names],kind)
        if lifecycle:
            bounds=value(label+'-boundaries.json')
            if bounds['logs']!=names: errors.append('log_boundaries_'+label)
            groups=bounds['groups'];previous=row['window']['start_ns']
            if len(groups)!=(4 if kind=='reuse' else 1): errors.append('group_count_'+label)
            for group in groups:
                if not previous<=group['start_ns']<group['end_ns']<=row['window']['end_ns']:
                    errors.append('group_window_'+label)
                previous=group['end_ns']
        if truth['status']!='PASS': errors.append('truth_'+label)
        if scope['status']!='PASS': errors.append('scope_'+label)
        cases.append(dict(label=label,session_id=sid,truth=truth,scope=scope['status']))
        for suffix,data in (('record',row),('report',report),('truth',truth),('scope',scope)):
            (output/(sid+'.'+suffix+'.json')).write_text(json.dumps(data,indent=2))
        (output/(sid+'.jsonl')).write_bytes(capture)
    for native in (0,1):
        logs=[files.get(prefix+'off%d-%d.log'%(native,i),'') for i in range(2)]
        for log in logs:
            done=[json.loads(line.split(' ',1)[1]) for line in log.splitlines() if line.startswith('CIS_FD_DONE ')]
            if len(done)!=1 or done[0] != dict(threads=2,operations_per_thread=16,native=native,failed=0): errors.append('off_smoke')
    if lifecycle:
        logs=[files.get(prefix+'offcross-%d.log'%i,'') for i in range(2)]
        for log in logs:
            done=[json.loads(line.split(' ',1)[1]) for line in log.splitlines() if line.startswith('CIS_FD_DONE ')]
            if len(done)!=1 or done[0] != dict(threads=1,operations_per_thread=16,native=0,failed=0): errors.append('off_cross_smoke')
    result=dict(schema='cis-fd-vm-check-v1',status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),cases=cases,
                source=declared['source'],serial_sha256=hashlib.sha256(raw).hexdigest(),
                analyzer_sha256={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                 for name in ('fd_vm_check.py','fd_check.py','explain.py','owner_report.py')},
                scope='FD selected-source bridge only; incomplete X1 stage',
                pending=(['rwsem reader set','selected spinlock owner','full quality/recall and cost acceptance'] if lifecycle else
                         ['explicit cross-container CLONE_FILES','FD destruction/address-reuse runtime','rwsem reader set']),
                x1_stage='INCOMPLETE',performance_certification='NOT_ACCEPTED')
    (output/'verification.json').write_text(json.dumps(result,indent=2));return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('serial',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();result=verify(args.serial,args.output)
    print(json.dumps({key:result[key] for key in ('status','errors','cases','scope','x1_stage')}))
    raise SystemExit(result['status']!='PASS')
