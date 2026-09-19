# SPDX-License-Identifier: GPL-2.0
import argparse
import hashlib
import json
from pathlib import Path

from block_fixture_check import case_order,check_case,check_counters,FIXTURES
from block_report import analyze
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate
import block_merge_check


def verify(serial,output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes(); text=raw.decode(); files=extract(text); prefix='/tmp/block-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    plan,declared,permit=[value(k+'.json') for k in ('plan','result','permit')]
    fixture=plan.get('fixture')
    merging=fixture in ('merge','merge-scheduler'); scheduler=fixture=='merge-scheduler'
    if fixture is not None and fixture not in FIXTURES: raise ValueError('fixture mode')
    output.mkdir(mode=0o700); errors=[]; states=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or 'CIS_BLOCK_DEVICE_UNLOAD=0' not in text.splitlines(): errors.append('guest_exit_or_unload')
    if any(s in text for s in ('BUG: KASAN:','Oops:','Kernel panic','WARNING: CPU:')): errors.append('kernel_warning')
    order=block_merge_check.case_order(scheduler) if merging else case_order()
    if (plan.get('order')!=order or plan.get('rounds')!=3 or
            plan.get('operations_per_actor')!=(None if merging else 8) or
            plan.get('device_bytes')!=16<<20 or plan.get('direct') is not (not merging) or plan.get('bytes_per_io')!=4096 or
            plan.get('verify_head_bio_blkcg') is not True): errors.append('frozen_plan')
    cases=block_merge_check.SCHEDULER_CASES if scheduler else block_merge_check.CASES
    if merging and plan.get('cases')!={k:list(v) for k,v in cases.items()}:
        errors.append('merge_cases')
    if scheduler and plan.get('scheduler')!='mq-deadline': errors.append('scheduler_plan')
    if plan.get('devices')!=(['/dev/cisblock0','/dev/cisblock1'] if fixture else ['/dev/vda','/dev/vdb']):
        errors.append('device_plan')
    if any(declared['source'].get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    for label in order:
        ev=value(label+'-evidence.json'); logs=[files[prefix+label+'-%d.log'%i] for i in range(2)]
        report=None; identities=None
        if '-block' in label:
            sid=str(ev['session_id'])
            if not sid.isascii() or not sid.isdigit(): raise ValueError('session id')
            record=value('records/'+sid+'.json')
            if any(record.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source_'+label)
            capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
            report=analyze(record,capture); identities=[record['root_identities'][key] for key in ev['targets']]
            if record['nonce']!=label.replace('-','') or record['window']!=ev['window'] or not record['objects_absent']:
                errors.append('session_boundary_'+label)
            validate(ev['active_sources'],'block',record['receipt']['prepared_ns'],record['window']['end_ns'])
            validate(ev['idle_sources'],None,record['window']['end_ns'],2**64-1)
            programs=record['receipt'].get('program_audit',{})
            if (programs.get('required') is not True or programs.get('valid') is not True or
                    programs.get('programs')!=len(record['inventory']['program_names']) or programs.get('recursion_misses')!=0): errors.append('program_audit_'+label)
            (output/(label+'-report.json')).write_text(json.dumps(report,indent=2))
        else:
            validate(ev['active_sources'],None,0,2**64-1); validate(ev['idle_sources'],None,0,2**64-1)
        result=(block_merge_check.check_case(label.split('-')[0],ev['window'],logs,report,identities) if merging else
                check_case(label.split('-')[0],ev['window'],logs,report,identities,
                    verify_blkcg=plan.get('verify_head_bio_blkcg',False),fixture=fixture))
        if merging:
            result['fixture_counters']=block_merge_check.check_counters(ev['before']['fixture_counters'],ev['after']['fixture_counters'],result)
            if result['fixture_counters']['status']!='PASS': errors.append('fixture_counters_'+label)
        elif fixture:
            result['fixture_counters']=check_counters(fixture,ev['before']['fixture_counters'],ev['after']['fixture_counters'])
            if result['fixture_counters']['status']!='PASS': errors.append('fixture_counters_'+label)
        if result['status']!='PASS' or ev['exit_codes']!=[0,0]: errors.append(label)
        states.append(dict(label=label,result=result))
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,states=states,source=declared['source'],
        serial_sha256=hashlib.sha256(raw).hexdigest(),scope='native direct I/O request lifecycle; no unique blocker inference',
        fixture=fixture,performance_certification='NOT_ACCEPTED')
    (output/'verification.json').write_text(json.dumps(result,indent=2)); return result


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    args=p.parse_args(); r=verify(args.serial,args.output)
    print(json.dumps(dict(status=r['status'],errors=r['errors'],states=len(r['states']))))
    raise SystemExit(r['status']!='PASS')
