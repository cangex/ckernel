#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent replay of raw counter VM evidence, not its declared PASS."""
import argparse
import hashlib
import json
from pathlib import Path

from session_check import extract
from prototype_admission import SOURCE_KEYS
from collector_manifest import validate_inventory
from collector_audit import audit
from counter_report import analyze
from counter_check import check
from source_switches import validate
from counter_source_audit import delta
from owner_report import fields

CASES = ['sameLeaf','sameAncestor','private','limitFailure','frequency','migration']
LIFETIME_CASES = CASES + ['reuse','privateCpu']


def verify(serial, output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    data=serial.read_bytes(); text=data.decode(); files=extract(text)
    prefix='/tmp/counter-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    output.mkdir(mode=0o700)
    plan, declared, permit = [value(name+'.json') for name in ('plan','result','permit')]
    errors=[]; cases=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): errors.append('guest_exit')
    if any(word in text for word in ('page_counter underflow:', 'BUG: KASAN:', 'Oops:', 'Kernel panic', 'WARNING: CPU:')):
        errors.append('kernel_warning_or_failure')
    lifetime=plan.get('lifetime_protocol')==2
    planned=LIFETIME_CASES if lifetime else CASES
    if plan.get('cases')!=planned or plan.get('repetitions')!=3 or plan.get('sample_shift')!=0:
        errors.append('frozen_plan')
    if lifetime and (plan.get('private_cpu')!=0 or plan.get('private_spin_ms')!=3): errors.append('private_cpu_plan')
    expected={case+str(i) for i in range(3) for case in planned}
    if {r['label'] for r in declared['cases']}!=expected or len(declared['cases'])!=len(expected): errors.append('declared_set')
    if any(declared['source'].get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    rows=[]
    for path,body in files.items():
        if path.startswith(prefix+'records/') and path.endswith('.json'):
            row=json.JSONDecoder().raw_decode(body.lstrip())[0]
            if 'session_id' in row: rows.append(row)
    if len(rows)!=len(expected) or {r['nonce'] for r in rows}!=expected: errors.append('capture_set')
    for row in rows:
        label=row['nonce']; sid=str(row['session_id'])
        if label not in expected or not sid.isascii() or not sid.isdigit(): raise ValueError('case identity')
        if any(row.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source_'+label)
        validate_inventory('counter',row['inventory'])
        capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
        report=analyze(row,capture); scope=audit(row,capture)
        kind=label[:-1]; logs=[files[prefix+label+'-%d.log'%i] for i in range(2)]
        bounds=value(label+'-boundaries.json')
        truth=check(report,logs,kind not in ('private','privateCpu','reuse'),kind=='limitFailure',
                    [row['root_identities'][key] for key in bounds['targets']])
        source_audit=None
        if lifetime:
            source_audit=delta(bounds['source_before'],bounds['source_after'],0)
            if source_audit!=bounds['source_delta']: errors.append('source_audit_'+label)
            if not (bounds['source_before']['after_ns']<=row['requested_ns'] and
                    row['window']['end_ns']<=bounds['source_after']['before_ns']):
                errors.append('source_audit_boundary_'+label)
            ts=[[fields(line) for line in log.splitlines() if line.startswith('CIS_COUNTER_TRUTH ')] for log in logs]
            if not all(t.get('leaf_generation',0)>0 and t.get('parent_generation',0)>0 for actor in ts for t in actor):
                errors.append('missing_generation_truth_'+label)
            if kind=='reuse':
                resets=[fields(line) for line in files[prefix+label+'-reset.log'].splitlines() if line.startswith('CIS_COUNTER_RESET ')]
                if len(resets)!=1 or not all(ts): raise ValueError('reset truth')
                reset=resets[0]; first,second=ts[0][0],ts[1][0]
                if (reset['slot']!=0 or first['leaf']!=second['leaf'] or first['parent']!=second['parent'] or
                        max(t['end_ns'] for t in ts[0])>=min(t['begin_ns'] for t in ts[1]) or
                        first['leaf_generation']!=reset['old_leaf0'] or second['leaf_generation']!=reset['new_leaf0'] or
                        first['parent_generation']!=reset['old_parent'] or second['parent_generation']!=reset['new_parent'] or
                        reset['old_parent']==reset['new_parent'] or reset['old_leaf0']==reset['new_leaf0']):
                    errors.append('reuse_generation_boundary_'+label)
            if kind=='privateCpu' and any(t['cpu']!=0 for actor in ts for t in actor):
                errors.append('private_cpu_binding_'+label)
        expected_ops=24 if kind=='frequency' else 32
        if truth['truth_operations']!=expected_ops: errors.append('truth_population_'+label)
        if truth['matched_calls']!=truth['eligible_calls']: errors.append('eligible_recall_'+label)
        validate(bounds['active_sources'],'counter',row['requested_ns'],row['window']['end_ns'])
        validate(bounds['idle_sources'],None,row['window']['end_ns'],2**64-1)
        if truth['status']!='PASS' or scope['status']!='PASS': errors.append('case_'+label)
        cases.append(dict(label=label,truth=truth,scope=scope['status'],calls=len(report['calls']),source_audit=source_audit))
        for suffix,result in (('record',row),('report',report),('truth',truth),('scope',scope)):
            (output/(sid+'.'+suffix+'.json')).write_text(json.dumps(result,indent=2))
        (output/(sid+'.jsonl')).write_bytes(capture)
    result=dict(status='FAIL' if errors else 'PASS', errors=sorted(set(errors)),cases=cases,
                source=declared['source'],serial_sha256=hashlib.sha256(data).hexdigest(),
                scope='stable fixture update/rollback attribution only; X2 incomplete',
                x2_status='INCOMPLETE',performance_certification='NOT_ACCEPTED',
                lifetime_cohort=lifetime,
                pending=([] if lifetime else ['native counter lifetime and address reuse'])+
                        ['bounded selected-ancestor aggregation','high-rate source audit',
                         'complete cost and updated ordinary memcg bridge','conditional hardware evidence'])
    (output/'verification.json').write_text(json.dumps(result,indent=2))
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    args=p.parse_args(); r=verify(args.serial,args.output)
    print(json.dumps(dict(status=r['status'],errors=r['errors'],cases=len(r['cases']))))
    raise SystemExit(r['status']!='PASS')
