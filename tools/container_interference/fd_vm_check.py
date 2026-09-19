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
from fd_population_check import check_population
from owner_report import fields
from source_switches import validate as validate_sources


def verify_boundaries(bounds, names, logs, window, requested_ns):
    errors=[]
    if bounds.get('logs')!=names or len(logs)!=len(names): errors.append('log_boundaries')
    groups=bounds.get('groups',[])
    if len(groups)*2!=len(names): errors.append('group_count')
    previous=requested_ns
    for index,group in enumerate(groups):
        # Namespace/cgroup preparation may precede the window. Actual fixture
        # operations must pass their barrier and fit both lifetime and window.
        if group.get('generation')!=index or not previous<=group['start_ns']<group['end_ns']<=window['end_ns']:
            errors.append('group_order')
        previous=group['end_ns']
        for text in logs[index*2:index*2+2]:
            events=[json.loads(line.split(' ',1)[1]) for line in text.splitlines() if line.startswith('CIS_FD_TRUTH ')]
            if not events: errors.append('missing_operation_boundaries')
            for event in events:
                if not max(window['start_ns'],group['start_ns'])<=event['begin_ns']<event['released_ns']<=min(window['end_ns'],group['end_ns']):
                    errors.append('operation_outside_window_or_lifetime')
    return sorted(set(errors))


def verify_reuse_retirement(raw, logs):
    events=[fields(row['detail']) for row in (json.loads(line) for line in raw.splitlines())
            if row.get('kind')=='OWNER']
    events=[event for event in events if event.get('resource')==3]
    objects={};errors=[];verified=0
    for text in logs:
        truth=[json.loads(line.split(' ',1)[1]) for line in text.splitlines() if line.startswith('CIS_FD_TRUTH ')]
        if not truth: errors.append('missing_lifetime_truth');continue
        keys={(row['object'],row['tgid']) for row in truth}
        if len(keys)!=1: errors.append('mixed_lifetime_truth');continue
        obj,tgid=keys.pop()
        objects.setdefault(obj,[]).append(dict(tgid=tgid,begin=min(row['begin_ns'] for row in truth),
                                              end=max(row['released_ns'] for row in truth)))
    for obj,lifetimes in objects.items():
        lifetimes.sort(key=lambda row:row['begin'])
        for old,new in zip(lifetimes,lifetimes[1:]):
            retire=[event for event in events if event['object']==obj and event['phase']==8 and
                    old['end']<=event['sample_time_ns']<new['begin']]
            old_epochs={event['epoch'] for event in events if event['object']==obj and event['phase']==2 and event['actor_tid']>>32==old['tgid']}
            new_epochs={event['epoch'] for event in events if event['object']==obj and event['phase']==2 and event['actor_tid']>>32==new['tgid']}
            if not retire or len(old_epochs)!=1 or len(new_epochs)!=1 or old_epochs & new_epochs:
                errors.append('missing_retirement_or_new_watch');continue
            if not min(new_epochs)>max(event['sample_time_ns'] for event in retire):
                errors.append('new_watch_precedes_retirement');continue
            verified+=1
    if not verified: errors.append('no_verified_retirement_reuse')
    return dict(status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),verified_reuses=verified)


def verify(serial, output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes();text=raw.decode();files=extract(text);prefix='/tmp/fd-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    declared,plan,permit=[value(name+'.json') for name in ('result','plan','permit')]
    output.mkdir(mode=0o700);errors=[];cases=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): errors.append('guest_exit')
    lifecycle=plan.get('suite')=='lifecycle'
    collector=plan.get('collector','owner')  # Older immutable cohorts used the combined source.
    if collector not in ('fd','owner'): raise ValueError('unsupported FD cohort collector')
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
        if row.get('collector')!=collector: errors.append('collector_'+label)
        validate_inventory(collector,row['inventory'])
        capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
        report=explain(row,capture);scope=audit(row,capture)
        kind=label[:-1]
        names=([label+'g%d-%d.log'%(g,i) for g in range(4) for i in range(2)] if kind=='reuse'
               else [label+'-%d.log'%i for i in range(2)])
        truth=check(report,[files[prefix+name] for name in names],kind)
        population=check_population([files[prefix+name] for name in names],capture,row['window'],kind,plan.get('population'))
        retirement=None
        if collector=='fd':
            bounds=value(label+'-boundaries.json')
            validate_sources(bounds['active_sources'],'fd',row['requested_ns'],row['window']['end_ns'])
            validate_sources(bounds['idle_sources'],None,row['window']['end_ns'],2**64-1)
        if lifecycle:
            bounds=value(label+'-boundaries.json')
            errors += [error+'_'+label for error in verify_boundaries(bounds,names,
                        [files[prefix+name] for name in names],row['window'],row['requested_ns'])]
            if kind=='reuse' and any('helper_affinity_restored=1' not in files[prefix+name] for name in names):
                errors.append('reuse_allocation_setup_'+label)
            if kind=='reuse':
                retirement=verify_reuse_retirement(capture,[files[prefix+name] for name in names])
                if retirement['status']!='PASS' or retirement['verified_reuses']!=truth['observed_address_reuses']:
                    errors.append('reuse_retirement_'+label)
        if truth['status']!='PASS': errors.append('truth_'+label)
        if scope['status']!='PASS': errors.append('scope_'+label)
        if population['status']!='PASS_SCOPED': errors.append('population_'+label)
        cases.append(dict(label=label,session_id=sid,truth=truth,scope=scope['status'],retirement=retirement,
                          population={k:v for k,v in population.items() if k!='calls'}))
        for suffix,data in (('record',row),('report',report),('truth',truth),('scope',scope),('population',population)):
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
                                 for name in ('fd_vm_check.py','fd_check.py','fd_population_check.py','explain.py','owner_report.py')},
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
