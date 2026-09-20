# SPDX-License-Identifier: GPL-2.0
import argparse
import hashlib
import json
from pathlib import Path

from block_report import analyze
from tag_fixture_check import order, check
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate
from collector_manifest import contract


def verify(serial, output):
    if serial.stat().st_size>128<<20: raise ValueError('serial bound')
    raw=serial.read_bytes(); text=raw.decode(); files=extract(text); prefix='/tmp/tag-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    plan,declared,permit=[value(k+'.json') for k in ('plan','result','permit')]
    output.mkdir(mode=0o700); errors=[]; states=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or 'CIS_TAG_DEVICE_UNLOAD=0' not in text.splitlines():
        errors.append('guest_exit_or_unload')
    if any(x in text for x in ('BUG: KASAN:','Oops:','Kernel panic','WARNING: CPU:')):
        errors.append('kernel_warning')
    pressure=plan.get('pressure',False)
    if (type(pressure) is not bool or plan.get('order')!=order(pressure) or plan.get('depth')!=4 or plan.get('rounds')!=3
            or plan.get('release_delay_s')!=.05 or plan.get('fixture')!='blk_mq_alloc_request'):
        errors.append('frozen_plan')
    if any(declared['source'].get(k)!=permit['source'].get(k) for k in SOURCE_KEYS):
        errors.append('source_binding')
    if [s['label'] for s in declared['states']]!=order(pressure): errors.append('state_order')
    for label in order(pressure):
        ev=value(label+'-evidence.json'); report=None; identities=None
        if '-block-' in label:
            sid=str(ev['session_id'])
            if not sid.isascii() or not sid.isdigit(): raise ValueError('session id')
            record=value('records/'+sid+'.json')
            if any(record.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source_'+label)
            capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
            report=analyze(record,capture)
            identities=[record['root_identities'][t] for t in ev['targets']]
            if record['nonce']!=label.replace('-','').replace('_','') or record['window']!=ev['window'] or not record['objects_absent']:
                errors.append('boundary_'+label)
            validate(ev['active_sources'],'block',record['receipt']['prepared_ns'],record['window']['end_ns'])
            validate(ev['idle_sources'],None,record['window']['end_ns'],2**64-1)
            audit=record['receipt'].get('program_audit',{})
            program_count=len(contract('block')['programs']) if pressure else 8
            if audit.get('required') is not True or audit.get('valid') is not True or audit.get('programs')!=program_count or audit.get('recursion_misses')!=0:
                errors.append('program_audit_'+label)
            (output/(label+'-report.json')).write_text(json.dumps(report,indent=2))
        else:
            validate(ev['active_sources'],None,0,2**64-1); validate(ev['idle_sources'],None,0,2**64-1)
        result=check(ev,report,identities)
        if result['status']!='PASS' or ev['exit_codes']!=[0,0]: errors.append(label)
        states.append(dict(label=label,result=result))
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,states=states,source=declared['source'],
                serial_sha256=hashlib.sha256(raw).hexdigest(),performance_certification='NOT_ACCEPTED',
                scope='native blk-mq API tag wait fixture; no unique blocking-container inference')
    (output/'verification.json').write_text(json.dumps(result,indent=2))
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    a=p.parse_args(); result=verify(a.serial,a.output)
    print(json.dumps(dict(status=result['status'],errors=result['errors'],states=len(result['states']))))
    raise SystemExit(result['status']!='PASS')
