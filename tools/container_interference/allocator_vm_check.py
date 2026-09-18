# SPDX-License-Identifier: GPL-2.0
"""Ordinary workload bridge checks; no fabricated event-recall denominator."""
import argparse
import hashlib
import json
from pathlib import Path

from allocator_report import analyze
from owner_report import fields
from session_check import extract
from source_switches import validate
from prototype_admission import SOURCE_KEYS
from allocator_source_audit import delta as source_delta
from allocator_fixture_check import CASES, case_order, check_case

ORDER=['off0','allocator0','allocator1','off1','off2','allocator2']


def check_work(window,logs,report=None,identities=None):
    errors=[]; operations=[]; participants=[]
    if len(logs)!=2: raise ValueError('two actors required')
    for index,log in enumerate(logs):
        pids=[fields(line).get('host_pid',0) for line in log.splitlines() if line.startswith('CIS_SESSION_CONTAINER ')]
        rows=[fields(line) for line in log.splitlines() if line.startswith('CIS_ALLOC_OP ')]
        if (len(pids)!=1 or not pids[0] or [r['index'] for r in rows]!=list(range(8)) or
                any(r['success']!=1 or r['split_regions']!=128 or
                    not window['start_ns']<=r['begin_ns']<r['end_ns']<=window['end_ns'] for r in rows)):
            errors.append('workload_'+str(index))
        operations.append(rows)
        if report is not None:
            identity=identities[index]
            calls=[c for c in report['calls'] if c['actor'][:2]==[identity['id'],identity['generation']]
                   and len(pids)==1 and c['actor'][2] & 0xffffffff == pids[0]
                   and any(r['begin_ns']<=c['interval_ns'][0]<=c['interval_ns'][1]<=r['end_ns'] for r in rows)]
            if any(c['sample_shift']!=6 for c in calls): errors.append('sampling_rule_'+str(index))
            if not calls: errors.append('no_in_operation_allocation_'+str(index))
            if calls and not any(any('mt_alloc' in f or 'mas_' in f for f in c['stack_leaf_to_root']) for c in calls):
                errors.append('no_maple_stack_'+str(index))
            participants.append(dict(id=identity,calls=len(calls),
                stage_kinds=sorted({p['kind'] for c in calls for p in c['phases']})))
    if report is not None and (report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS'):
        errors.append('capture_quality')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,operations=operations,participants=participants,
                recall=None,performance_certification='NOT_ACCEPTED')


def verify(serial,output,fixture=False):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes(); text=raw.decode(); files=extract(text)
    prefix='/tmp/allocator-fixture-evidence/' if fixture else '/tmp/allocator-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    plan,declared,permit=[value(k+'.json') for k in ('plan','result','permit')]
    output.mkdir(mode=0o700); errors=[]; states=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): errors.append('guest_exit')
    if any(s in text for s in ('BUG: KASAN:','Oops:','Kernel panic','WARNING: CPU:')): errors.append('kernel_warning')
    order=case_order() if fixture else ORDER
    if fixture:
        if (plan.get('order')!=order or plan.get('sample_shift')!=0 or plan.get('cache')!='cis_alloc_test' or
                plan.get('operations')!=4 or plan.get('cases')!=list(CASES) or plan.get('rounds')!=3):
            errors.append('frozen_plan')
        if 'CIS_ALLOC_FIXTURE_UNLOAD=0' not in text.splitlines(): errors.append('fixture_cleanup')
    elif (plan.get('order')!=order or plan.get('sample_shift')!=6 or plan.get('cache')!='maple_node' or
          plan.get('operations')!=8 or plan.get('split_regions')!=128): errors.append('frozen_plan')
    if any(declared['source'].get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    for label in order:
        ev=value(label+'-evidence.json'); logs=[files[prefix+label+'-%d.log'%i] for i in range(2)]
        report=None; identities=None
        if 'allocator' in label:
            sid=str(ev['session_id'])
            if not sid.isascii() or not sid.isdigit(): raise ValueError('session id')
            record=value('records/'+sid+'.json')
            if any(record.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source_'+label)
            capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
            report=analyze(record,capture)
            identities=[record['root_identities'][key] for key in ev['targets']]
            if record['nonce']!=label.replace('-','') or record['window']!=ev['window'] or not record['objects_absent']:
                errors.append('session_boundary_'+label)
            # Sources are attached before the future common business window.
            validate(ev['active_sources'],'allocator',record['receipt']['prepared_ns'],record['window']['end_ns'])
            validate(ev['idle_sources'],None,record['window']['end_ns'],2**64-1)
            (output/(label+'-report.json')).write_text(json.dumps(report,indent=2))
        else:
            validate(ev['active_sources'],None,0,2**64-1); validate(ev['idle_sources'],None,0,2**64-1)
        result=check_case(label.split('-')[0],ev['window'],logs,report,identities) if fixture else check_work(ev['window'],logs,report,identities)
        audit=source_delta(ev['source_before'],ev['source_after'],
                           shift=0 if fixture else 6, cache='cis_alloc_test' if fixture else 'maple_node')
        if 'off' in label and any(audit['totals'].values()): errors.append('off_not_quiet_'+label)
        if 'allocator' in label and audit['totals']['sampled']==0: errors.append('source_not_sampled_'+label)
        if result['status']!='PASS' or ev['exit_codes']!=[0,0]: errors.append(label)
        states.append(dict(label=label,result=result,source_audit=audit))
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,states=states,source=declared['source'],
        serial_sha256=hashlib.sha256(raw).hexdigest(),scope='native allocator fixture only' if fixture else 'ordinary VMA bridge only',
        x3_status='INCOMPLETE',performance_certification='NOT_ACCEPTED')
    (output/'verification.json').write_text(json.dumps(result,indent=2)); return result


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    p.add_argument('--fixture',action='store_true')
    args=p.parse_args(); r=verify(args.serial,args.output,args.fixture)
    print(json.dumps(dict(status=r['status'],errors=r['errors'],states=len(r['states']))))
    raise SystemExit(r['status']!='PASS')
