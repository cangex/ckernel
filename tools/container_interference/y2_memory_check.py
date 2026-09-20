#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent replay of Y2 resource identity and node selection evidence."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import statistics

from collector_manifest import validate_record_inventory
from collector_audit import audit
from counter_report import analyze as counter_analyze
from page_backend_report import analyze as page_analyze
from counter_mem_check import counts, operations
from owner_report import fields
from prototype_admission import SOURCE_KEYS
from session_check import extract
from source_switches import validate


def counter_ownership(report,actors,roots,common):
    """A private parent stays private even though higher ancestors are common."""
    errors=[]; seen=defaultdict(set); calls_by_actor=defaultdict(int)
    for call in report['calls']:
        actor=tuple(call['actor'][:2])
        if actor not in actors: errors.append('unexpected_actor'); continue
        index=actors.index(actor); leaf=roots[index]['cgroup_id']; parent=roots[index]['parent_id']
        owners={s['owner_cgroup'] for s in call['steps'] if s['resource_kind']=='memory'}
        if owners and call['operation'] in ('charge','try_charge','uncharge') and (leaf not in owners or parent not in owners or common not in owners):
            errors.append('incomplete_native_owner_chain')
        calls_by_actor[actor]+=1
        for s in call['steps']:
            if s['owner_cgroup']: seen[s['owner_cgroup']].add(actor)
    if any(not calls_by_actor[a] for a in actors): errors.append('missing_actor_calls')
    if seen[common]!=set(actors): errors.append('common_ancestor_not_observed')
    for index,root in enumerate(roots):
        expected={a for a,r in zip(actors,roots) if r['parent_id']==root['parent_id']}
        if seen[root['parent_id']]!=expected: errors.append('private_parent_cross_attribution')
        if seen[root['cgroup_id']]!={actors[index]}: errors.append('private_leaf_cross_attribution')
    return dict(status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),
                calls_per_actor={str(k):v for k,v in calls_by_actor.items()},
                native_owner_participants={str(k):[list(a) for a in sorted(v)] for k,v in seen.items()},
                blocker='NOT_INFERRED',cacheline_contention='UNVERIFIED')


def audit_totals(text):
    values=defaultdict(int)
    for line in text.splitlines():
        d=fields(line)
        if 'cpu' not in d: continue
        for k,v in d.items():
            if k!='cpu' and type(v) is int and not k.endswith('max_ns'): values[k]+=v
    return dict(values)


def verify(serial,output):
    if serial.stat().st_size>128<<20: raise ValueError('serial capacity')
    raw_serial=serial.read_bytes(); text=raw_serial.decode(); files=extract(text)
    prefix='/tmp/y2-memory-evidence/'
    def value(name): return json.JSONDecoder().raw_decode(files[prefix+name].lstrip())[0]
    output.mkdir(mode=0o700)
    plan,result,permit=[value(n+'.json') for n in ('plan','result','permit')]
    errors=[]; states=[]
    if 'CIS_PROFILE_VM_EXIT=0' not in text.splitlines(): errors.append('guest_exit')
    if any(v in text for v in ('page_counter underflow:', 'BUG: KASAN:', 'Oops:', 'Kernel panic','WARNING: CPU:')):
        errors.append('kernel_warning')
    lease=value('lease-checks.json')
    if lease.get('status')!='PASS' or len(lease.get('checks',[]))!=6: errors.append('lease_control')
    if (plan['schema'] not in ('cis-y2-memory-plan-v1','cis-y2-memory-plan-v2') or len(plan['order'])!=24 or
            plan['operations']!=16 or plan['sample_shift']!=6 or plan['cpus']!=[0,1] or plan['mems']!=[0]):
        errors.append('plan')
    if [s['label'] for s in result['states']]!=[s['label'] for s in plan['order']]: errors.append('state_order')
    if any(result['source'].get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('source_binding')
    captures=[p for p in files if p.startswith(prefix+'records/') and p.endswith('.json')]
    records=[json.JSONDecoder().raw_decode(files[p].lstrip())[0] for p in captures]
    records=[r for r in records if 'session_id' in r]
    if len(records)!=12: errors.append('capture_count')
    for expected in plan['order']:
        label=expected['label']; ev=value(label+'-evidence.json'); c=expected['case']
        if any(ev.get(k)!=v for k,v in expected.items()): errors.append('plan_state_'+label)
        if ev['exit_codes']!=[0,0]: errors.append('workload_exit_'+label)
        logs=[files[prefix+job['log']] for job in ev['jobs']]
        page_case=plan['schema']=='cis-y2-memory-plan-v2' and c['collector']=='page_backend'
        if page_case and (plan['page_operations']!=8 or plan['page_bytes_per_operation']!=64<<20 or plan['page_thp']!='MADV_NOHUGEPAGE'):
            errors.append('page_workload_plan')
        ops=[operations(log,ev['window'],8 if page_case else 16,(64 if page_case else 8)<<20) for log in logs]
        for i,index in enumerate(c['actors']):
            before,after=[ev[edge]['roots'][index] for edge in ('before','after')]
            cb,ca=[counts(d['cpu.stat']) for d in (before,after)]
            eb,ea=[counts(d['memory.events']) for d in (before,after)]
            delta={k:ea[k]-eb[k] for k in eb}
            if any(delta.get(k,0) for k in ('oom','oom_kill','max')): errors.append('memory_failure_'+label)
            if any(d['cpuset.mems.effective'].strip()!='0' for d in (before,after)): errors.append('memory_placement_'+label)
            ops[i].update(cgroup_cpu_usage_usec=ca['usage_usec']-cb['usage_usec'],
                memory_before_bytes=int(before['memory.current']),memory_after_bytes=int(after['memory.current']),
                cumulative_memory_peak_bytes=int(after['memory.peak']),memory_events_delta=delta)
        entry=dict(label=label,case=c['name'],round=ev['round'],enabled=ev['enabled'],actors=ops,source_audit={})
        for name in ('page_audit','counter_audit'):
            b,a=[audit_totals(ev[e][name]) for e in ('before','after')]
            delta={k:a[k]-b.get(k,0) for k in a}
            if any(v<0 for v in delta.values()): errors.append('audit_regression_'+label)
            if not ev['enabled'] and any(delta.values()): errors.append('source_running_while_off_'+label)
            entry['source_audit'][name]=delta
        if ev['enabled']:
            matching=[r for r in records if r['nonce']==label]
            if len(matching)!=1: raise ValueError('unique session required')
            record=matching[0]; sid=str(record['session_id'])
            if record['window']!=ev['window'] or sid!=str(ev['session_id']): errors.append('window_'+label)
            if any(record.get(k)!=permit['source'].get(k) for k in SOURCE_KEYS): errors.append('session_source_'+label)
            validate_record_inventory(record)
            raw=(files[prefix+'records/'+sid+'.jsonl'].rstrip()+'\n').encode()
            report=(counter_analyze if c['collector']=='counter' else page_analyze)(record,raw)
            scope=audit(record,raw)
            if report['quality']['status']!='PASS' or scope['status']!='PASS': errors.append('capture_'+label)
            identities=[record['root_identities'][ev['targets'][i]] for i in c['actors']]
            actors=[(d['id'],d['generation']) for d in identities]
            if c['collector']=='counter':
                op_rows=[[fields(line) for line in log.splitlines() if line.startswith('CIS_MEM_OP ')] for log in logs]
                workload_calls=[call for call in report['calls'] for i,a in enumerate(actors)
                    if tuple(call['actor'][:2])==a and any(op['begin_ns']<=call['interval_ns'][0]<call['interval_ns'][1]<=op['end_ns'] for op in op_rows[i])]
                ownership=counter_ownership(dict(calls=workload_calls),actors,[plan['roots'][i] for i in c['actors']],plan['common_cgroup_id'])
                if ownership['status']!='PASS': errors.append('ownership_'+label)
                entry['ownership']=ownership
            else:
                episodes=report['episodes']; by_actor=defaultdict(list)
                for e in episodes:
                    by_actor[tuple(e['actor'][:2])].append(e)
                    if e['holder'] is not None or e['blocking_container'] is not None: errors.append('invented_holder_'+label)
                if c['name']=='zone1' and episodes: errors.append('outside_selected_node_'+label)
                if c['name']=='zone0' and any(not by_actor[a] for a in actors): errors.append('missing_page_actor_'+label)
                if c['name']=='zone0' and not report['shared_backends']: errors.append('common_zone_missing_'+label)
                entry.update(page_episodes=len(episodes),same_zone_resources=report['shared_backends'],
                    wait_wall_ns=[e['wait_to_acquire_wall_ns'] for e in episodes],
                    hold_wall_ns=[e['held_inner_wall_ns'] for e in episodes],
                    operations=sorted({e['operation'] for e in episodes}))
            validate(ev['active_sources'],c['collector'],record['requested_ns'],record['window']['end_ns'])
            entry.update(process_capturing_cpu_ns=record['process_cpu_budget']['phase_peak_cpu_ns']['CAPTURING'],
                combined_process_rss_peak_bytes=record['combined_rss_peak_bytes'],excluded=report['excluded'])
            for suffix,obj in (('record',record),('report',report),('scope',scope)):
                (output/(label+'.'+suffix+'.json')).write_text(json.dumps(obj,indent=2))
            (output/(label+'.jsonl')).write_bytes(raw)
        else:
            if ev['session_id'] is not None: errors.append('off_session')
            validate(ev['active_sources'],None,ev['window']['start_ns'],ev['window']['end_ns'])
        validate(ev['idle_sources'],None,ev['window']['start_ns'],2**64-1)
        states.append(entry)
    pairs=[]
    for repeat in range(3):
        for c in plan['cases']:
            off,on=[next(s for s in states if s['round']==repeat and s['case']==c['name'] and s['enabled']==v) for v in (False,True)]
            for actor,(a,b) in enumerate(zip(off['actors'],on['actors'])):
                pairs.append(dict(round=repeat,case=c['name'],actor=actor,
                    throughput_change_pct=(b['operations_per_second']/a['operations_per_second']-1)*100,
                    operation_median_change_pct=(statistics.median(b['operation_wall_ns'])/statistics.median(a['operation_wall_ns'])-1)*100,
                    cgroup_cpu_delta_usec=b['cgroup_cpu_usage_usec']-a['cgroup_cpu_usage_usec']))
    report=dict(status='FAIL' if errors else 'PASS_SCOPED',errors=sorted(set(errors)),states=states,
        source=result['source'],serial_sha256=hashlib.sha256(raw_serial).hexdigest(),lease_control=lease,
        paired_descriptive_changes=pairs,scope='Y2 native ancestor identity and page-zone selection, not complete Y2/Y7 acceptance',
        limits=['8 or 16 operations per actor; all samples retained, P99 not estimated',
                'source audit includes host/background entries; process costs exclude source-side CPU',
                'shared counter/zone participation is not contention or a uniquely blocking tenant',
                'reclaim, SLUB selected-node runtime and joint costs require separate evidence'])
    (output/'verification.json').write_text(json.dumps(report,indent=2))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('serial',type=Path); p.add_argument('output',type=Path)
    a=p.parse_args(); r=verify(a.serial,a.output)
    print(json.dumps(dict(status=r['status'],errors=r['errors'],states=len(r['states']))))
    raise SystemExit(r['status']!='PASS_SCOPED')
