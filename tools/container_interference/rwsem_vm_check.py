#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import argparse
import hashlib
import json
from pathlib import Path
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate
from rwsem_report import analyze
from rwsem_fixture_check import check as fixture

CASES=('writeRead','writeWrite','readers','private','tryFailure','abort','nonOwner','preWindow','reuse','downgrade')

def check(serial, output):
    raw=serial.read_bytes()
    if len(raw)>128<<20: raise ValueError('serial capacity')
    text=raw.decode(); files=extract(text); prefix='/tmp/rwsem-evidence/'
    value=lambda name: json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    plan=value('plan.json'); result=value('result.json'); permit=value('permit.json')
    if (plan['schema']!='cis-rwsem-vm-plan-v1' or plan['cases'] not in (list(CASES),['overflow']) or
        plan['rounds']!=3 or plan['eligible_min_overlap_ns']!=1_000_000 or plan['reader_limit']!=8 or
        plan['target_indices']!=[0,1] or plan['registered_roots']!=4): raise ValueError('unexpected frozen plan')
    output.mkdir(mode=0o700); errors=[]; states=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or 'CIS_RWSEM_FIXTURE_UNLOAD=0' not in text.splitlines(): errors.append('guest_cleanup')
    if any(v in text for v in ('Oops:','Kernel panic','BUG: KASAN:','WARNING: CPU:')): errors.append('kernel_warning')
    if result['source']!=plan['source'] or any(plan['source'][k]!=permit['source'][k] for k in SOURCE_KEYS): errors.append('source_binding')
    order=[(r,c,e) for r in range(3) for c in plan['cases'] for e in ((False,True) if r%2==0 else (True,False))]
    if len(result['states'])!=len(order): errors.append('incomplete_matrix')
    for r,c,e in order:
        label='%s%d-%s'%(c,r,'on' if e else 'off'); state=value(label+'-evidence.json')
        if (state['round'],state['case'],state['enabled'])!=(r,c,e): errors.append('state_binding')
        if any(code!=0 for code in state['exit_codes']) or len(state['exit_codes'])!=len(state['jobs']): errors.append('workload_exit_'+label)
        logs={name:files[prefix+name] for name in state['logs']}; report=None; record=None
        if e:
            sid=state['session_id']; record=value('records/'+sid+'.json')
            if record['collector']!='rwsem' or record['nonce']!=label or record['targets']!=state['targets']: errors.append('capture_binding_'+label)
            if any(record.get(k)!=plan['source'][k] for k in SOURCE_KEYS): errors.append('record_source_'+label)
            report=analyze(record,(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode())
            if not record.get('objects_absent'): errors.append('collector_cleanup_'+label)
            validate(state['active_sources'],'rwsem',record['receipt']['prepared_ns'],record['window']['end_ns'])
            validate(state['idle_sources'],None,record['window']['end_ns'],2**64-1)
            identities=[record['owner_identities'].get(k,record['root_identities'].get(k)) for k in state['registered']]
            truth=fixture(report,state['jobs'],logs,identities,c,record['window'])
            (output/(label+'-report.json')).write_text(json.dumps(report,indent=2))
            cost=dict(cpu=record.get('process_cpu_budget'),rss_bytes=record.get('combined_rss_peak_bytes'))
        else:
            validate(state['active_sources'],None,0,2**64-1); validate(state['idle_sources'],None,0,2**64-1)
            truth=fixture(None,state['jobs'],logs,[dict(id=i,generation=0) for i in range(4)],c,None); cost=None
        if truth['status']=='FAIL': errors.append(label+':'+','.join(truth['errors']))
        states.append(dict(label=label,truth=truth,cost=cost))
    verification=dict(schema='cis-rwsem-vm-check-v1',status='FAIL' if errors else 'PASS_SCOPED',errors=errors,
        serial_sha256=hashlib.sha256(raw).hexdigest(),source=plan['source'],states=states,
        x7_complete=False,limits=['fixture public API coverage only','reader set not complete','no full-kernel performance certification'])
    (output/'verification.json').write_text(json.dumps(verification,indent=2)); return verification

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path); a=p.parse_args()
    r=check(a.serial,a.output); print(json.dumps(dict(status=r['status'],errors=r['errors'],states=len(r['states']))))
    raise SystemExit(r['status']=='FAIL')
