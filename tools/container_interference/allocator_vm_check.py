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


def check_work(window,logs,report=None,identities=None,require_maple=False):
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
            contexts=[c.get('maple_context') for c in calls if c.get('maple_context')]
            if require_maple and (not calls or len(contexts)!=len(calls)):
                errors.append('missing_maple_context_'+str(index))
            participants.append(dict(id=identity,calls=len(calls),
                maple_contexts=len(contexts),tree_addresses=sorted({c['tree_address'] for c in contexts}),
                stage_kinds=sorted({p['kind'] for c in calls for p in c['phases']})))
    if report is not None and (report['quality']['status']!='PASS' or report['scope_audit']['status']!='PASS'):
        errors.append('capture_quality')
    if report is not None and report.get('lifetimes',{}).get('status')=='FAIL':
        errors.append('release_quality')
    if report is not None and require_maple:
        if report.get('maple',{}).get('status')!='PASS': errors.append('maple_quality')
        if len(participants)==2 and set(participants[0]['tree_addresses']) & set(participants[1]['tree_addresses']):
            errors.append('private_mm_tree_conflation')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,operations=operations,participants=participants,
                recall=None,performance_certification='NOT_ACCEPTED')


def verify(serial,output,fixture=False,placement=False,failure=False,rollback=False,maple=False,backend_only=False):
    if backend_only and (not fixture or any((placement,failure,rollback,maple))):
        raise ValueError('dedicated selected-backend fixture required')
    collector='alloc_backend' if backend_only else 'allocator'
    if maple and any((fixture,placement,failure,rollback)): raise ValueError('separate Maple cohort')
    if maple:
        from maple_fixture_check import check_work as verify_work
    else:
        verify_work=check_work
    verify_case=check_case; cases=CASES; fixture_order=case_order
    if sum((placement,failure,rollback))>1: raise ValueError('separate cohorts required')
    if placement:
        fixture=True
        from allocator_placement_check import check_case as verify_case, CASES as cases, case_order as fixture_order, nodes
    if failure:
        fixture=True
        from allocator_failure_check import check_case as verify_case, CASES as cases, case_order as fixture_order, SETTINGS
    if rollback:
        fixture=True
        from allocator_rollback_check import check_case as verify_case, CASES as cases, case_order as fixture_order, SETTINGS
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw=serial.read_bytes(); text=raw.decode(); files=extract(text)
    prefix='/tmp/maple-evidence/' if maple else '/tmp/allocator-rollback-evidence/' if rollback else '/tmp/allocator-failure-evidence/' if failure else '/tmp/allocator-placement-evidence/' if placement else '/tmp/allocator-fixture-evidence/' if fixture else '/tmp/allocator-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    plan,declared,permit=[value(k+'.json') for k in ('plan','result','permit')]
    output.mkdir(mode=0o700); errors=[]; states=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): errors.append('guest_exit')
    if any(s in text for s in ('BUG: KASAN:','Oops:','Kernel panic','WARNING: CPU:')): errors.append('kernel_warning')
    order=fixture_order() if fixture else ORDER
    if backend_only and (plan.get('collector')!='alloc_backend' or plan.get('boot_cache')!='maple_node' or
            plan.get('maple_context') is not False or plan.get('backend')!=dict(cache='cis_alloc_test',nodes=[])):
        errors.append('backend_selection_plan')
    if placement and (plan.get('placement') is not True or plan.get('topology')!={'0':'0-3','1':'4-7'}):
        errors.append('frozen_numa_topology')
    if failure or rollback:
        expected_fault=dict(settings=SETTINGS,caches={} if rollback else dict(cis_alloc_test='1',cis_alloc_private='0'))
        if plan.get('rollback' if rollback else 'failure') is not True or plan.get('fault_configuration')!=expected_fault: errors.append('frozen_fault')
        fault_name='fail_page_alloc' if rollback else 'failslab'
        original=value(fault_name+'-original.json'); restored=value(fault_name+'-restored.json')
        if original!=restored or original['settings']['probability']!='0' or any(v!='0' for v in original['caches'].values()):
            errors.append('failslab_restore')
        if rollback and plan.get('geometry')!={k:dict(object_size='65536',objs_per_slab='1') for k in ('cis_alloc_test','cis_alloc_private')}:
            errors.append('rollback_cache_geometry')
    if maple:
        if (plan.get('maple_fixture') is not True or plan.get('maple_context') is not True or
                plan.get('sample_shift')!=0 or plan.get('cache')!='maple_node' or
                plan.get('cycles')!=2 or plan.get('entries')!=32 or plan.get('order')!=ORDER): errors.append('frozen_maple_plan')
        if 'CIS_MAPLE_FIXTURE_UNLOAD=0' not in text.splitlines(): errors.append('maple_cleanup')
    elif fixture:
        if (plan.get('order')!=order or plan.get('sample_shift')!=0 or plan.get('cache')!='cis_alloc_test' or
                plan.get('operations')!=(8 if placement or failure else 4) or plan.get('cases')!=list(cases) or plan.get('rounds')!=3 or not plan.get('release_tracking')):
            errors.append('frozen_plan')
        if 'CIS_ALLOC_FIXTURE_UNLOAD=0' not in text.splitlines(): errors.append('fixture_cleanup')
    elif (plan.get('order')!=order or plan.get('sample_shift')!=6 or plan.get('cache')!='maple_node' or
          plan.get('operations')!=8 or plan.get('split_regions')!=128): errors.append('frozen_plan')
    if any(declared['source'].get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    for label in order:
        ev=value(label+'-evidence.json'); logs=[files[prefix+label+'-%d.log'%i] for i in range(2)]
        if placement:
            expected=[dict(cpu=str(i),mems=str(n)) for i,n in enumerate(nodes(label.split('-')[0]))]
            if ev.get('placement_before')!=expected or ev.get('placement_after')!=expected: errors.append('cpuset_boundary_'+label)
        if (failure or rollback) and (ev.get('fault_before')!=expected_fault or ev.get('fault_after')!=expected_fault):
            errors.append('failslab_boundary_'+label)
        report=None; identities=None
        if 'allocator' in label:
            sid=str(ev['session_id'])
            if not sid.isascii() or not sid.isdigit(): raise ValueError('session id')
            record=value('records/'+sid+'.json')
            if record['collector']!=collector: errors.append('collector_'+label)
            if backend_only and record.get('backend_selection')!=plan['backend']: errors.append('backend_binding_'+label)
            if any(record.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source_'+label)
            capture=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
            report=analyze(record,capture)
            identities=[record['root_identities'][key] for key in ev['targets']]
            if record['nonce']!=label.replace('-','') or record['window']!=ev['window'] or not record['objects_absent']:
                errors.append('session_boundary_'+label)
            # Sources are attached before the future common business window.
            validate(ev['active_sources'],collector,record['receipt']['prepared_ns'],record['window']['end_ns'])
            validate(ev['idle_sources'],None,record['window']['end_ns'],2**64-1)
            (output/(label+'-report.json')).write_text(json.dumps(report,indent=2))
        else:
            validate(ev['active_sources'],None,0,2**64-1); validate(ev['idle_sources'],None,0,2**64-1)
        result=verify_case(label.split('-')[0],ev['window'],logs,report,identities,require_releases=True) if fixture else verify_work(ev['window'],logs,report,identities,**({} if maple else {'require_maple':plan.get('maple_context') is True}))
        audit=source_delta(ev['source_before'],ev['source_after'],
                           shift=0 if fixture or maple else 6, cache=plan.get('boot_cache','cis_alloc_test' if fixture else 'maple_node'))
        if 'off' in label and any(audit['totals'].values()): errors.append('off_not_quiet_'+label)
        if 'allocator' in label and audit['totals']['sampled']==0: errors.append('source_not_sampled_'+label)
        if result['status']!='PASS' or ev['exit_codes']!=[0,0]: errors.append(label)
        states.append(dict(label=label,result=result,source_audit=audit))
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,states=states,source=declared['source'],
        serial_sha256=hashlib.sha256(raw).hexdigest(),scope='native Maple destination/copy/reuse fixture only' if maple else 'native page-allocation failure and partial bulk rollback fixture only' if rollback else 'native failslab pre-hook fixture only' if failure else 'two-node allowed-placement fixture only' if placement else 'native allocator fixture only' if fixture else 'ordinary VMA bridge only',
        x3_status='INCOMPLETE',performance_certification='NOT_ACCEPTED')
    (output/'verification.json').write_text(json.dumps(result,indent=2)); return result


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    p.add_argument('--fixture',action='store_true')
    p.add_argument('--placement',action='store_true')
    p.add_argument('--failure',action='store_true')
    p.add_argument('--rollback',action='store_true')
    p.add_argument('--maple',action='store_true')
    p.add_argument('--backend-only',action='store_true')
    args=p.parse_args(); r=verify(args.serial,args.output,args.fixture,args.placement,args.failure,args.rollback,args.maple,args.backend_only)
    print(json.dumps(dict(status=r['status'],errors=r['errors'],states=len(r['states']))))
    raise SystemExit(r['status']!='PASS')
