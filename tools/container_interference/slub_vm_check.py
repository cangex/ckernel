#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import argparse
import hashlib
import json
from pathlib import Path
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate
from collector_audit import audit
from session_quality import assess
from slub_fixture_check import check as fixture

CASES_V1=('shared','private','switch','recreate','native')
CASES=('shared','private','switch','recreate','unseenHolder','native')
CASES_SELECTED=CASES+('outsideNode','outsideCache')


def check(serial, output):
    raw=serial.read_bytes()
    if len(raw)>128<<20: raise ValueError('serial capacity')
    text=raw.decode(); files=extract(text); prefix='/tmp/slub-evidence/'
    value=lambda name: json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    plan=value('plan.json'); result=value('result.json'); permit=value('permit.json')
    selected=plan['schema']=='cis-slub-vm-plan-v3'
    cases=CASES_SELECTED if selected else CASES_V1 if plan['schema']=='cis-slub-vm-plan-v1' else CASES
    if (plan['schema'] not in ('cis-slub-vm-plan-v1','cis-slub-vm-plan-v2','cis-slub-vm-plan-v3') or plan['cases']!=list(cases) or plan['rounds']!=3 or
        plan['eligible_min_overlap_ns']!=100_000 or plan['hold_us']!=5000 or plan['window_ms']!=2000 or
        plan['target_indices']!=[0,1] or plan['registered_roots']!=4 or plan['nodes']!=[0,1]):
        raise ValueError('unexpected frozen plan')
    output.mkdir(mode=0o700); errors=[]; states=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or 'CIS_SLUB_FIXTURE_UNLOAD=0' not in text.splitlines(): errors.append('guest_cleanup')
    if any(v in text for v in ('Oops:','Kernel panic','BUG: KASAN:','WARNING: CPU:')): errors.append('kernel_warning')
    if result['source']!=plan['source'] or any(plan['source'][k]!=permit['source'][k] for k in SOURCE_KEYS): errors.append('source_binding')
    if plan['schema'] in ('cis-slub-vm-plan-v2','cis-slub-vm-plan-v3') and plan.get('recreated_watch')!='target warmup before non-target holder':
        raise ValueError('recreated watch precondition')
    if selected and plan.get('selection')!=dict(cache='cis_slub_fixture',nodes=[0]): raise ValueError('source selection plan')
    order=[(r,c,e) for r in range(3) for c in cases for e in ((False,True) if r%2==0 else (True,False))]
    if len(result['states'])!=len(order): errors.append('incomplete_matrix')
    for r,c,e in order:
        label='%s%d-%s'%(c,r,'on' if e else 'off'); state=value(label+'-evidence.json')
        if (state['round'],state['case'],state['enabled'])!=(r,c,e) or state!=result['states'][len(states)]: errors.append('state_binding')
        if any(v!=0 for v in state['exit_codes']) or len(state['exit_codes'])!=len(state['jobs']): errors.append('workload_exit_'+label)
        logs={j['log']:files[prefix+j['log']] for j in state['jobs']}
        events=None; window=None; cost=None; quality=None; scope=None
        identities=[dict(id=i+1,generation=1) for i in range(4)]
        if e:
            sid=state['session_id']; record=value('records/'+sid+'.json')
            raw_events=files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n'
            events=[json.loads(line) for line in raw_events.splitlines()]
            if any(str(event.get('session_id'))!=str(sid) for event in events): errors.append('event_binding_'+label)
            if record['collector']!='slub' or record['nonce']!=label.replace('-','') or record['targets']!=state['targets']: errors.append('capture_binding_'+label)
            if selected and record.get('backend_selection')!=dict(cache='cis_not_selected' if c=='outsideCache' else 'cis_slub_fixture',nodes=[0]): errors.append('cache_node_selection_'+label)
            if any(record.get(k)!=plan['source'][k] for k in SOURCE_KEYS): errors.append('record_source_'+label)
            quality=assess(record); scope=audit(record,raw_events); window=record['window']
            if quality['status']!='PASS' or scope['status']!='PASS': errors.append('capture_quality_'+label)
            validate(state['active_sources'],'slub',record['receipt']['prepared_ns'],window['end_ns'])
            validate(state['idle_sources'],None,window['end_ns'],2**64-1)
            identities=[record['owner_identities'].get(k,record['root_identities'].get(k)) for k in state['registered']]
            cost=dict(cpu=record.get('process_cpu_budget'),rss_bytes=record.get('combined_rss_peak_bytes'))
        else:
            validate(state['active_sources'],None,0,2**64-1); validate(state['idle_sources'],None,0,2**64-1)
        truth=fixture(events,state['jobs'],logs,identities,c,window)
        if truth['status']=='FAIL': errors.append(label+':'+','.join(truth['errors']))
        states.append(dict(label=label,truth=truth,cost=cost,quality=quality,scope=scope))
    verification=dict(schema='cis-slub-vm-check-v1',status='FAIL' if errors else 'PASS_SCOPED',errors=errors,
        serial_sha256=hashlib.sha256(raw).hexdigest(),source=plan['source'],states=states,x7_complete=False,
        limits=['controlled native node lock, not workload prevalence','ordinary bridge has no independent holder recall',
                'IRQ/pre-window holders unknown','VM host steal not observed','full observer CPU and production acceptance pending'])
    (output/'verification.json').write_text(json.dumps(verification,indent=2)); return verification


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path); a=p.parse_args()
    r=check(a.serial,a.output); print(json.dumps(dict(status=r['status'],errors=r['errors'],states=len(r['states']))))
    raise SystemExit(r['status']=='FAIL')
