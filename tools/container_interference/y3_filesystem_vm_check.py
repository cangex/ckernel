#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import argparse
import hashlib
import json
from pathlib import Path

from filesystem_report import analyze
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate
from y2_memory_check import audit_totals
from y3_filesystem_check import CASES,case_order,check_case


def verify(serial,output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes(); text=raw.decode(); files=extract(text); prefix='/tmp/y3-filesystem-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    output.mkdir(mode=0o700); errors=[]; states=[]; leases=[]
    plan,declared,permit=[value(k+'.json') for k in ('plan','result','permit')]
    lease_tests=value('lease-checks.json')
    if lease_tests.get('status')!='PASS' or lease_tests.get('checks')!=[
            'invalid_input','invalid_fd','non_ext4_rejected','exclusive','immutable',
            'inherited_fd_not_authority','new_lease_generation']:
        errors.append('lease_control')
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines() or 'CIS_FILESYSTEM_UNLOAD=0' not in text.splitlines():
        errors.append('guest_exit_or_unload')
    if any(s in text for s in ('BUG: KASAN:','Oops:','Kernel panic','WARNING: CPU:')): errors.append('kernel_warning')
    if (plan.get('schema')!='cis-y3-filesystem-plan-v1' or plan.get('order')!=case_order() or plan.get('cases')!=CASES or
            plan.get('iterations')!=96 or plan.get('bytes_per_file')!=65536 or plan.get('private_directories') is not True or
            plan.get('features')!=['legacy_orphan_list','orphan_file'] or plan.get('cpus')!=[0,1] or
            plan.get('window_ms')!=2000 or plan.get('manager_cpu')!=7): errors.append('frozen_plan')
    if [s['label'] for s in declared['states']]!=[s['label'] for s in case_order()]: errors.append('state_order')
    if any(declared['source'].get(k)!=permit['source'].get(k) or plan['source'].get(k)!=permit['source'].get(k)
           for k in SOURCE_KEYS): errors.append('source_binding')
    for expected in case_order():
        label=expected['label']; ev=value(label+'-evidence.json')
        if any(ev.get(k)!=v for k,v in expected.items()): errors.append('state_plan_'+label)
        logs=[files[prefix+label+'-%d.log'%i] for i in range(2)]
        report=None; identities=None; costs={}
        b,a=[audit_totals(ev[e]['native_audit']) for e in ('before','after')]
        delta={k:a[k]-b[k] for k in b}
        if any(v<0 for v in delta.values()) or delta.get('recursive',0): errors.append('native_audit_'+label)
        if not ev['enabled'] and any(delta.values()): errors.append('source_running_while_off_'+label)
        if ev['enabled']:
            sid=str(ev['session_id'])
            if not sid.isascii() or not sid.isdigit(): raise ValueError('session id')
            record=value('records/'+sid+'.json')
            if any(record.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source_'+label)
            capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
            report=analyze(record,capture); identities=[record['root_identities'][t] for t in ev['targets']]
            if (record['nonce']!=label or record['window']!=ev['window'] or not record['objects_absent'] or
                    record.get('filesystem_selection')!='/fs%d'%CASES[ev['case']]['selected']):
                errors.append('session_boundary_'+label)
            validate(ev['active_sources'],'filesystem',record['requested_ns'],record['window']['end_ns'])
            programs=record['receipt'].get('program_audit',{})
            if (programs.get('required') is not True or programs.get('valid') is not True or
                    programs.get('programs')!=1 or programs.get('recursion_misses')!=0):
                errors.append('program_audit_'+label)
            selected=report['scope_audit']['filesystem_selection']
            if selected: leases.append(selected['lease'])
            if ev['case'] in ('separate','unselected') and not delta['filtered']:
                errors.append('missing_unselected_source_filter_'+label)
            costs=dict(process_capturing_cpu_ns=record['process_cpu_budget']['phase_peak_cpu_ns']['CAPTURING'],
                       combined_process_rss_peak_bytes=record['combined_rss_peak_bytes'])
            (output/(label+'-report.json')).write_text(json.dumps(report,indent=2))
            (output/(label+'-record.json')).write_text(json.dumps(record,indent=2))
            (output/(label+'.jsonl')).write_bytes(capture)
        else:
            validate(ev['active_sources'],None,0,2**64-1)
            if ev['session_id'] is not None: errors.append('off_session_'+label)
        validate(ev['idle_sources'],None,ev['window']['start_ns'],2**64-1)
        checked=check_case(ev['case'],ev['window'],logs,report,identities)
        if checked['status']!='PASS' or ev['exit_codes']!=[0,0]: errors.append(label)
        for edge in ('before','after'):
            for root in ev[edge]['roots']:
                values=dict(line.split() for line in root['memory.events'].splitlines())
                if any(int(values.get(k,0)) for k in ('oom','oom_kill','max')): errors.append('resource_error_'+label)
        states.append(dict(**expected,result=checked,native_source_delta=delta,costs=costs,
                           coverage=report['coverage'] if report else None))
    if len(leases)!=12 or leases!=sorted(set(leases)): errors.append('lease_reuse_or_nonmonotonic')
    result=dict(status='FAIL' if errors else 'PASS_SCOPED',errors=errors,states=states,source=declared['source'],
        serial_sha256=hashlib.sha256(raw).hexdigest(),leases=leases,
        scope='private directories on selected shared/separate ext4; public-resource use and journal wait observations',
        performance_certification='NOT_ACCEPTED',causal_blocking_tenant='NOT_IDENTIFIED',
        unimplemented=['allocation group holder ownership','read-only image cache contention','complete journal contributor lifetimes'])
    (output/'verification.json').write_text(json.dumps(result,indent=2)); return result


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    args=p.parse_args(); r=verify(args.serial,args.output)
    print(json.dumps(dict(status=r['status'],errors=r['errors'],states=len(r['states']))))
    raise SystemExit(r['status']!='PASS_SCOPED')
