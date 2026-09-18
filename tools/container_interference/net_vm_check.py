# SPDX-License-Identifier: GPL-2.0
import argparse
import hashlib
import json
from pathlib import Path

from net_fixture_check import CASES,case_order,check_case
from net_report import analyze
from net_source_audit import delta
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate


def verify(serial,output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes(); text=raw.decode(); files=extract(text); prefix='/tmp/net-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    plan,declared,permit=[value(k+'.json') for k in ('plan','result','permit')]
    output.mkdir(mode=0o700); errors=[]; states=[]
    cases=tuple(plan.get('cases',[]))
    if cases not in (CASES,('backlog',)): raise ValueError('unsupported frozen case set')
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or 'CIS_NET_FIXTURE_UNLOAD=0' not in text.splitlines():
        errors.append('guest_exit_or_unload')
    if any(s in text for s in ('BUG: KASAN:','Oops:','Kernel panic','WARNING: CPU:')): errors.append('kernel_warning')
    if (plan.get('order')!=case_order(cases) or plan.get('rounds')!=3 or
            plan.get('net_shift')!=0 or plan.get('hold_ms')!=30 or plan.get('operations')!=4): errors.append('frozen_plan')
    if any(declared['source'].get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    for label in case_order(cases):
        ev=value(label+'-evidence.json'); logs=[files[prefix+label+'-%d.log'%i] for i in range(2)]
        report=None; identities=None
        if '-net' in label:
            sid=str(ev['session_id'])
            if not sid.isascii() or not sid.isdigit(): raise ValueError('session id')
            record=value('records/'+sid+'.json')
            if any(record.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source_'+label)
            capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
            report=analyze(record,capture); identities=[record['root_identities'][key] for key in ev['targets']]
            if record['nonce']!=label.replace('-','') or record['window']!=ev['window'] or not record['objects_absent']:
                errors.append('session_boundary_'+label)
            validate(ev['active_sources'],'net',record['receipt']['prepared_ns'],record['window']['end_ns'])
            validate(ev['idle_sources'],None,record['window']['end_ns'],2**64-1)
            (output/(label+'-report.json')).write_text(json.dumps(report,indent=2))
        else:
            validate(ev['active_sources'],None,0,2**64-1); validate(ev['idle_sources'],None,0,2**64-1)
        result=check_case(label.split('-')[0],ev['window'],logs,report,identities)
        source=delta(ev['source_before'],ev['source_after'])
        if '-off' in label and any(source['totals'].values()): errors.append('off_not_quiet_'+label)
        if '-net' in label and (not source['totals']['selected'] or source['totals']['skipped']): errors.append('source_gap_'+label)
        if result['status']!='PASS' or ev['exit_codes']!=[0,0]: errors.append(label)
        states.append(dict(label=label,result=result,source_audit=source))
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,states=states,source=declared['source'],
        serial_sha256=hashlib.sha256(raw).hexdigest(),scope='native TCP logical lock fixture only',
        x4_status='INCOMPLETE',performance_certification='NOT_ACCEPTED')
    (output/'verification.json').write_text(json.dumps(result,indent=2)); return result


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    args=p.parse_args(); r=verify(args.serial,args.output)
    print(json.dumps(dict(status=r['status'],errors=r['errors'],states=len(r['states']))))
    raise SystemExit(r['status']!='PASS')
